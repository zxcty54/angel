import 'dart:convert';
import 'dart:math';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';
import '../data/demo_seed.dart';
import '../data/location_catalogue.dart';
import '../models/community.dart';
import '../models/location.dart';
import 'community_repository.dart';

/// Fully local demo, including durable posts, replies and reaction toggles.
/// Sample counts are initial fixture values, not claims about real neighbours.
class DemoRepository implements CommunityRepository {
  DemoRepository({
    this.preferences,
    this.delay = const Duration(milliseconds: 120),
  });
  final SharedPreferences? preferences;
  final Duration delay;
  static const storageKey = 'mohalla.demo.v1';
  final _uuid = const Uuid();
  final Map<String, CommunityPost> _posts = {};
  final Map<String, ThreadComment> _comments = {};
  late CommunityProfile _profile;
  @override
  bool get isDemo => true;
  @override
  CommunityProfile get currentProfile => _profile;

  @override
  Future<void> initialize() async {
    final raw = preferences?.getString(storageKey);
    if (raw != null) {
      try {
        final j = jsonDecode(raw) as Map<String, dynamic>;
        _profile = CommunityProfile.fromJson(
          Map<String, dynamic>.from(j['profile'] as Map),
        );
        for (final p in j['posts'] as List) {
          final post = CommunityPost.fromJson(
            Map<String, dynamic>.from(p as Map),
          );
          _posts[post.id] = post;
        }
        for (final c in j['comments'] as List) {
          final comment = ThreadComment.fromJson(
            Map<String, dynamic>.from(c as Map),
          );
          _comments[comment.id] = comment;
        }
        return;
      } on Object {
        // Corrupt/older demo storage is not a live account. Re-seed safely.
        _posts.clear();
        _comments.clear();
      }
    }
    _posts.clear();
    _comments.clear();
    final seed = DemoSeed();
    _profile = seed.me;
    _posts.addEntries(seed.posts.map((p) => MapEntry(p.id, p)));
    _comments.addEntries(seed.comments.map((c) => MapEntry(c.id, c)));
    await _persist();
  }

  Future<void> _wait() => Future<void>.delayed(delay);
  Future<void> _persist() async {
    if (preferences == null) return;
    final saved = await preferences!.setString(
      storageKey,
      jsonEncode({
        'profile': _profile.toJson(),
        'posts': _posts.values.map((p) => p.toJson()).toList(),
        'comments': _comments.values.map((c) => c.toJson()).toList(),
      }),
    );
    if (!saved) {
      throw StateError(
        'Local storage is full. Please remove an image or free space.',
      );
    }
  }

  @override
  Future<List<AreaPath>> getLocations({String? district}) async =>
      district == null
      ? demoLocations
      : demoLocations.where((l) => l.district == district).toList();

  @override
  Future<FeedPage> getFeed(FeedQuery query, {FeedCursor? cursor}) async {
    await _wait();
    final needle = query.search.trim().toLowerCase();
    final result = _posts.values
        .where(
          (p) =>
              !p.hidden &&
              query.location.contains(p.location, query.scope) &&
              (query.type == null || p.type.key == query.type) &&
              (needle.isEmpty ||
                  '${p.title} ${p.description} ${p.landmark}'
                      .toLowerCase()
                      .contains(needle)),
        )
        .toList();
    result.sort((a, b) {
      if (query.sort == FeedSort.supported) {
        final score = b.upvotes.compareTo(a.upvotes);
        if (score != 0) return score;
      }
      final time = b.createdAt.compareTo(a.createdAt);
      return time == 0 ? b.id.compareTo(a.id) : time;
    });
    final page = result
        .where((p) {
          if (cursor == null) return true;
          if (query.sort == FeedSort.supported && p.upvotes != cursor.upvotes) {
            return p.upvotes < cursor.upvotes;
          }
          return p.createdAt.isBefore(cursor.createdAt) ||
              (p.createdAt.isAtSameMomentAs(cursor.createdAt) &&
                  p.id.compareTo(cursor.id) < 0);
        })
        .take(query.limit + 1)
        .toList();
    final hasMore = page.length > query.limit;
    final visible = page.take(query.limit).toList();
    return FeedPage(visible, hasMore ? visible.last.cursor : null);
  }

  CommunityPost _require(String id) {
    final p = _posts[id];
    if (p == null || p.hidden) {
      throw StateError('This post is no longer available.');
    }
    return p;
  }

  @override
  Future<CommunityPost?> getPost(String id) async {
    final p = _posts[id];
    return p == null || p.hidden ? null : p;
  }

  @override
  Future<List<CommunityPost>> getMyPosts() async =>
      _posts.values
          .where((p) => p.author.id == _profile.id && !p.hidden)
          .toList()
        ..sort((a, b) => b.createdAt.compareTo(a.createdAt));

  @override
  Future<CommunityPost> publish(PostDraft draft) async {
    draft.validate();
    await _wait();
    // Browsers have storage quotas: keep demo media lightweight; real backend allows 5MB.
    if (draft.images.fold<int>(0, (total, b) => total + b.length) >
        1500 * 1024) {
      throw ArgumentError(
        'Demo images together must be under 1.5 MB. Try a smaller photo.',
      );
    }
    final p = CommunityPost(
      id: _uuid.v4(),
      author: _profile,
      type: draft.type,
      title: draft.title.trim(),
      description: draft.description.trim(),
      location: draft.location,
      metadata: switch (draft.metadata) {
        IssueMetadata m => IssueMetadata(severity: m.severity),
        EventMetadata m => EventMetadata(date: m.date, venue: m.venue),
        _ => draft.metadata,
      },
      createdAt: DateTime.now().toUtc(),
      landmark: draft.landmark.trim(),
      latitude: draft.latitude == null
          ? null
          : double.parse(draft.latitude!.toStringAsFixed(3)),
      longitude: draft.longitude == null
          ? null
          : double.parse(draft.longitude!.toStringAsFixed(3)),
      mediaUrls: draft.images
          .map((bytes) => 'data:image/jpeg;base64,${base64Encode(bytes)}')
          .toList(),
    );
    _posts[p.id] = p;
    try {
      await _persist();
    } catch (_) {
      _posts.remove(p.id);
      rethrow;
    }
    return p;
  }

  @override
  Future<CommunityPost> setReaction(
    String postId,
    ReactionType type,
    bool active,
  ) async {
    final p = _require(postId);
    if (type == ReactionType.ditto && p.type != PostType.civicIssue ||
        type == ReactionType.rsvp && p.type != PostType.event) {
      throw ArgumentError('Reaction does not match post type.');
    }
    if (type == ReactionType.rsvp &&
        active &&
        (p.metadata as EventMetadata).hasEnded) {
      throw StateError('This event has ended.');
    }
    if (p.myReactions.contains(type) == active) {
      return p; // Idempotent desired-state API.
    }
    final reactions = {...p.myReactions};
    active ? reactions.add(type) : reactions.remove(type);
    final delta = active ? 1 : -1;
    PostMetadata metadata = p.metadata;
    if (type == ReactionType.ditto) {
      final m = metadata as IssueMetadata;
      metadata = m.copyWith(dittoCount: max(0, m.dittoCount + delta));
    }
    if (type == ReactionType.rsvp) {
      final m = metadata as EventMetadata;
      metadata = m.copyWith(rsvpCount: max(0, m.rsvpCount + delta));
    }
    final updated = p.copyWith(
      metadata: metadata,
      myReactions: reactions,
      upvotes: type == ReactionType.upvote
          ? max(0, p.upvotes + delta)
          : p.upvotes,
    );
    _posts[postId] = updated;
    try {
      await _persist();
    } catch (_) {
      _posts[postId] = p;
      rethrow;
    }
    return updated;
  }

  @override
  Future<List<ThreadComment>> getComments(String postId) async {
    _require(postId);
    await _wait();
    return _comments.values.where((c) => c.postId == postId).toList()
      ..sort((a, b) => a.createdAt.compareTo(b.createdAt));
  }

  @override
  Future<ThreadComment> addComment(
    String postId,
    String content, {
    String? parentId,
  }) async {
    final p = _require(postId);
    final text = content.trim();
    if (text.isEmpty || text.length > 2000) {
      throw ArgumentError('Reply must be 1–2000 characters.');
    }
    if (parentId != null) {
      var parent = _comments[parentId];
      if (parent == null || parent.postId != postId) {
        throw ArgumentError('Reply must belong to the same post.');
      }
      var depth = 1;
      while (parent!.parentId != null) {
        depth++;
        parent = _comments[parent.parentId];
      }
      if (depth > 3) {
        throw ArgumentError('Maximum reply depth is 3. Start a new comment.');
      }
    }
    final c = ThreadComment(
      id: _uuid.v4(),
      postId: postId,
      author: _profile,
      content: text,
      parentId: parentId,
      createdAt: DateTime.now().toUtc(),
    );
    _comments[c.id] = c;
    _posts[postId] = p.copyWith(commentCount: p.commentCount + 1);
    try {
      await _persist();
    } catch (_) {
      _comments.remove(c.id);
      _posts[postId] = p;
      rethrow;
    }
    return c;
  }

  @override
  Future<CommunityPost> setResolved(String postId, bool resolved) async {
    final p = _require(postId);
    if (p.author.id != _profile.id || p.type != PostType.civicIssue) {
      throw StateError('Only the author can mark their civic issue resolved.');
    }
    final next = p.copyWith(
      metadata: (p.metadata as IssueMetadata).copyWith(resolved: resolved),
    );
    _posts[postId] = next;
    try {
      await _persist();
    } catch (_) {
      _posts[postId] = p;
      rethrow;
    }
    return next;
  }

  @override
  Future<void> report(String postId, String reason) async {
    final p = _require(postId);
    if (reason.trim().isEmpty || reason.length > 300) {
      throw ArgumentError('Select a report reason.');
    }
    if (p.author.id == _profile.id) {
      throw StateError('You cannot report your own post.');
    }
    if (p.reported) return;
    _posts[postId] = p.copyWith(reported: true, flagCount: p.flagCount + 1);
    try {
      await _persist();
    } catch (_) {
      _posts[postId] = p;
      rethrow;
    }
  }

  @override
  Future<void> deletePost(String postId) async {
    final p = _require(postId);
    if (p.author.id != _profile.id) {
      throw StateError('Only the author can delete their post.');
    }
    final replies = _comments.values.where((c) => c.postId == postId).toList();
    _posts.remove(postId);
    _comments.removeWhere((_, c) => c.postId == postId);
    try {
      await _persist();
    } catch (_) {
      _posts[postId] = p;
      _comments.addEntries(replies.map((c) => MapEntry(c.id, c)));
      rethrow;
    }
  }

  @override
  Future<CommunityProfile> updateProfile(
    String name,
    AreaPath location,
    String landmark,
  ) async {
    if (name.trim().length < 2 || name.length > 100 || landmark.length > 150) {
      throw ArgumentError('Name must be 2–100 characters; landmark up to 150.');
    }
    final old = _profile;
    final oldPosts = Map<String, CommunityPost>.of(_posts);
    final oldComments = Map<String, ThreadComment>.of(_comments);
    _profile = _profile.copyWith(
      name: name.trim(),
      location: location,
      landmark: landmark.trim(),
    );
    for (final p in _posts.values.toList()) {
      if (p.author.id == _profile.id) {
        _posts[p.id] = p.copyWith(author: _profile);
      }
    }
    for (final c in _comments.values.toList()) {
      if (c.author.id == _profile.id) {
        _comments[c.id] = ThreadComment(
          id: c.id,
          postId: c.postId,
          author: _profile,
          content: c.content,
          createdAt: c.createdAt,
          parentId: c.parentId,
        );
      }
    }
    try {
      await _persist();
    } catch (_) {
      _profile = old;
      _posts
        ..clear()
        ..addAll(oldPosts);
      _comments
        ..clear()
        ..addAll(oldComments);
      rethrow;
    }
    return _profile;
  }

  @override
  Future<CommunityStats> getStats(AreaPath location) async {
    final posts = _posts.values
        .where(
          (p) => !p.hidden && location.contains(p.location, FeedScope.ward),
        )
        .toList();
    return CommunityStats(
      neighbours: {...posts.map((p) => p.author.id), _profile.id}.length,
      openIssues: posts
          .where((p) => p.type == PostType.civicIssue && !p.isResolved)
          .length,
      resolved: posts.where((p) => p.isResolved).length,
      events: posts
          .where(
            (p) =>
                p.metadata is EventMetadata &&
                !(p.metadata as EventMetadata).hasEnded,
          )
          .length,
    );
  }

  @override
  Future<void> signOut() async {
    /* Demo is a local sandbox, not an auth session. */
  }
  Future<void> reset() async {
    await preferences?.remove(storageKey);
    await initialize();
  }
}
