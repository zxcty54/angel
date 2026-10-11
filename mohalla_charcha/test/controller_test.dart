import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:mohalla_charcha/controllers/app_controller.dart';
import 'package:mohalla_charcha/data/location_catalogue.dart';
import 'package:mohalla_charcha/models/community.dart';
import 'package:mohalla_charcha/models/location.dart';
import 'package:mohalla_charcha/repositories/demo_repository.dart';

class RacingRepository extends DemoRepository {
  RacingRepository() : super(delay: Duration.zero);
  @override
  Future<FeedPage> getFeed(FeedQuery query, {FeedCursor? cursor}) async {
    if (query.type == 'local_review') {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    return super.getFeed(query, cursor: cursor);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('stale requests cannot overwrite a newly selected ward', () async {
    final c = AppController(RacingRepository());
    await c.initialize();
    final older = c.setFilter(PostType.localReview);
    final newer = c.selectLocation(demoLocations[4]);
    await Future.wait([older, newer]);
    expect(c.selectedLocation, demoLocations[4]);
    expect(c.posts.every((p) => p.location == demoLocations[4]), isTrue);
    expect(c.loading, isFalse);
    c.dispose();
  });
  test('changing district/ward clears old feed immediately', () async {
    final c = AppController(
      DemoRepository(delay: const Duration(milliseconds: 5)),
    );
    await c.initialize();
    final request = c.selectLocation(demoLocations[7]);
    expect(c.posts, isEmpty);
    await request;
    expect(c.posts.single.location.district, 'Gaya');
    c.dispose();
  });
  test('busy guard prevents double-tap toggling twice', () async {
    final c = AppController(DemoRepository(delay: Duration.zero));
    await c.initialize();
    final p = c.posts.first;
    await Future.wait([
      c.toggleReaction(p, ReactionType.upvote),
      c.toggleReaction(p, ReactionType.upvote),
    ]);
    expect(c.cachedPost(p.id)!.upvotes, p.upvotes + 1);
    expect(c.isBusy(p.id), isFalse);
    c.dispose();
  });
  test('bookmarks and language survive controller restart', () async {
    SharedPreferences.setMockInitialValues({});
    final prefs = await SharedPreferences.getInstance();
    final c = AppController(
      DemoRepository(preferences: prefs, delay: Duration.zero),
      preferences: prefs,
    );
    await c.initialize();
    final id = c.posts.first.id;
    await c.toggleSaved(id);
    await c.toggleLanguage();
    c.dispose();
    final next = AppController(
      DemoRepository(preferences: prefs, delay: Duration.zero),
      preferences: prefs,
    );
    await next.initialize();
    expect(next.isSaved(id), isTrue);
    expect(next.isHindi, isFalse);
    expect((await next.savedPosts()).single.id, id);
    next.dispose();
  });
  test('saving home updates location-first navigation', () async {
    final c = AppController(DemoRepository(delay: Duration.zero));
    await c.initialize();
    await c.saveProfile('Local neighbour', demoLocations[4], 'Near the park');
    expect(c.profile!.location, demoLocations[4]);
    expect(c.scope, FeedScope.ward);
    expect(c.posts.single.location, demoLocations[4]);
    c.dispose();
  });
}
