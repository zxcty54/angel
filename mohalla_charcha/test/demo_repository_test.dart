import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:mohalla_charcha/data/location_catalogue.dart';
import 'package:mohalla_charcha/models/community.dart';
import 'package:mohalla_charcha/models/location.dart';
import 'package:mohalla_charcha/repositories/demo_repository.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late DemoRepository repo;
  late SharedPreferences prefs;
  late CommunityPost issue;
  PostDraft newDraft({
    PostType type = PostType.general,
    PostMetadata metadata = const GeneralMetadata(),
  }) => PostDraft(
    type: type,
    title: 'Our new neighbourhood post',
    description: 'Let us do something useful together.',
    location: demoLocations.first,
    metadata: metadata,
  );
  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    prefs = await SharedPreferences.getInstance();
    repo = DemoRepository(preferences: prefs, delay: Duration.zero);
    await repo.initialize();
    issue = (await repo.getFeed(
      FeedQuery(location: demoLocations.first),
    )).posts.first;
  });
  test('ward feed is scoped and sorted', () async {
    final posts = (await repo.getFeed(
      FeedQuery(location: demoLocations.first),
    )).posts;
    expect(posts.length, 6);
    expect(posts.every((p) => p.location == demoLocations.first), isTrue);
    expect(posts.first.createdAt.isAfter(posts.last.createdAt), isTrue);
  });
  test('type and Hindi search filters work together', () async {
    final page = await repo.getFeed(
      FeedQuery(
        location: demoLocations.first,
        type: 'local_review',
        search: 'चाय',
      ),
    );
    expect(page.posts.length, 1);
    expect(page.posts.single.type, PostType.localReview);
  });
  test('rural path and broader block behave correctly', () async {
    expect(
      (await repo.getFeed(FeedQuery(location: demoLocations[4]))).posts.length,
      1,
    );
    expect(
      (await repo.getFeed(
        FeedQuery(location: demoLocations[4], scope: FeedScope.area),
      )).posts.length,
      2,
    );
    expect(
      (await repo.getFeed(
        FeedQuery(location: demoLocations[4], scope: FeedScope.block),
      )).posts.length,
      3,
    );
  });
  test('latest keyset pages do not duplicate posts', () async {
    final q = FeedQuery(location: demoLocations.first, limit: 2);
    final seen = <String>{};
    FeedCursor? cursor;
    do {
      final page = await repo.getFeed(q, cursor: cursor);
      for (final p in page.posts) {
        expect(seen.add(p.id), isTrue);
      }
      cursor = page.nextCursor;
    } while (cursor != null);
    expect(seen.length, 6);
  });
  test('supported sort orders by authoritative counts', () async {
    final page = await repo.getFeed(
      FeedQuery(location: demoLocations.first, sort: FeedSort.supported),
    );
    expect(page.posts.first.upvotes, 58);
  });
  test('upvotes are desired-state idempotent and reversible', () async {
    final active = await repo.setReaction(issue.id, ReactionType.upvote, true);
    expect(active.upvotes, issue.upvotes + 1);
    expect(
      (await repo.setReaction(issue.id, ReactionType.upvote, true)).upvotes,
      active.upvotes,
    );
    expect(
      (await repo.setReaction(issue.id, ReactionType.upvote, false)).upvotes,
      issue.upvotes,
    );
    expect(
      (await repo.setReaction(issue.id, ReactionType.upvote, false)).upvotes,
      issue.upvotes,
    );
  });
  test('ditto modifies civic metadata only', () async {
    final updated = await repo.setReaction(issue.id, ReactionType.ditto, true);
    expect(
      (updated.metadata as IssueMetadata).dittoCount,
      (issue.metadata as IssueMetadata).dittoCount + 1,
    );
    final general = await repo.publish(newDraft());
    await expectLater(
      repo.setReaction(general.id, ReactionType.ditto, true),
      throwsArgumentError,
    );
  });
  test('RSVP toggles independently', () async {
    final event = (await repo.getFeed(
      FeedQuery(location: demoLocations.first, type: 'event'),
    )).posts.single;
    final updated = await repo.setReaction(event.id, ReactionType.rsvp, true);
    expect(
      (updated.metadata as EventMetadata).rsvpCount,
      (event.metadata as EventMetadata).rsvpCount + 1,
    );
    expect(updated.upvotes, event.upvotes);
  });
  test('new civic post cannot inject resolution or ditto count', () async {
    final p = await repo.publish(
      newDraft(
        type: PostType.civicIssue,
        metadata: const IssueMetadata(resolved: true, dittoCount: 999),
      ),
    );
    expect((p.metadata as IssueMetadata).resolved, isFalse);
    expect((p.metadata as IssueMetadata).dittoCount, 0);
  });
  test('comments allow three levels but reject foreign parents', () async {
    final c0 = await repo.addComment(issue.id, 'A root comment');
    final c1 = await repo.addComment(issue.id, 'Level one', parentId: c0.id);
    final c2 = await repo.addComment(issue.id, 'Level two', parentId: c1.id);
    final c3 = await repo.addComment(issue.id, 'Level three', parentId: c2.id);
    await expectLater(
      repo.addComment(issue.id, 'Too deep', parentId: c3.id),
      throwsArgumentError,
    );
    final other = await repo.publish(newDraft());
    await expectLater(
      repo.addComment(other.id, 'Foreign reply', parentId: c0.id),
      throwsArgumentError,
    );
    expect((await repo.getPost(issue.id))!.commentCount, 7);
  });
  test('only author can resolve civic posts', () async {
    await expectLater(repo.setResolved(issue.id, true), throwsStateError);
    final own = await repo.publish(
      newDraft(type: PostType.civicIssue, metadata: const IssueMetadata()),
    );
    expect((await repo.setResolved(own.id, true)).isResolved, isTrue);
    expect((await repo.setResolved(own.id, false)).isResolved, isFalse);
  });
  test('duplicate reports never inflate counts; no auto-hide', () async {
    await repo.report(issue.id, 'spam');
    await repo.report(issue.id, 'spam');
    final p = (await repo.getPost(issue.id))!;
    expect(p.flagCount, 1);
    expect(p.reported, isTrue);
    expect(p.hidden, isFalse);
  });
  test('only author can delete; own deletion removes replies', () async {
    await expectLater(repo.deletePost(issue.id), throwsStateError);
    final p = await repo.publish(newDraft());
    await repo.addComment(p.id, 'My comment');
    await repo.deletePost(p.id);
    expect(await repo.getPost(p.id), isNull);
  });
  test('posts, comments and reactions survive reload', () async {
    final p = await repo.publish(newDraft());
    await repo.addComment(p.id, 'Persistent reply');
    await repo.setReaction(p.id, ReactionType.upvote, true);
    final reloaded = DemoRepository(preferences: prefs, delay: Duration.zero);
    await reloaded.initialize();
    expect((await reloaded.getPost(p.id))!.upvotes, 1);
    expect(
      (await reloaded.getComments(p.id)).single.content,
      'Persistent reply',
    );
  });
  test(
    'profile edits propagate name without retagging existing posts',
    () async {
      await repo.updateProfile(
        'New neighbour',
        demoLocations[4],
        'Near a public park',
      );
      final own = (await repo.getMyPosts()).single;
      expect(own.author.name, 'New neighbour');
      expect(own.location, demoLocations.first);
      expect(repo.currentProfile.location, demoLocations[4]);
    },
  );
  test('reset removes local creations and reaction changes', () async {
    final p = await repo.publish(newDraft());
    await repo.setReaction(issue.id, ReactionType.upvote, true);
    await repo.reset();
    expect(await repo.getPost(p.id), isNull);
    expect((await repo.getPost(issue.id))!.upvotes, issue.upvotes);
  });
  test('corrupt demo storage recovers safely', () async {
    await prefs.setString(DemoRepository.storageKey, '{broken JSON');
    final recovered = DemoRepository(preferences: prefs, delay: Duration.zero);
    await recovered.initialize();
    expect(
      (await recovered.getFeed(
        FeedQuery(location: demoLocations.first),
      )).posts.length,
      6,
    );
  });
}
