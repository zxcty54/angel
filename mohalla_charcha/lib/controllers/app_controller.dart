import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import '../models/community.dart';
import '../models/location.dart';
import '../repositories/community_repository.dart';
import '../services/onboarding_service.dart';

class AppController extends ChangeNotifier {
  AppController(this.repository, {this.preferences})
    : onboarding = OnboardingService(preferences);
  final CommunityRepository repository;
  final SharedPreferences? preferences;
  final OnboardingService onboarding;

  bool get hasCompletedWelcome => onboarding.isComplete;

  Future<void> completeWelcome() async {
    await onboarding.complete();
    _emit();
  }

  final _catalogue = <String, List<AreaPath>>{};
  final _cache = <String, CommunityPost>{};
  final _busy = <String>{};
  final _bookmarks = <String>{};
  int _generation = 0;
  String? _activeQuery;
  bool _disposed = false;
  bool initialized = false;
  bool loading = false;
  bool loadingMore = false;
  String? error;
  bool isHindi = false; // English default; Hindi toggle persists per device
  int tab = 0;
  AreaPath? selectedLocation;
  FeedScope scope = FeedScope.ward;
  FeedSort sort = FeedSort.latest;
  PostType? filter;
  String search = '';
  List<CommunityPost> posts = [];
  FeedCursor? _cursor;
  CommunityStats stats = const CommunityStats();

  CommunityProfile? get profile => repository.currentProfile;
  bool get isDemo => repository.isDemo;
  bool get hasMore => _cursor != null;
  bool get hasSession =>
      isDemo || Supabase.instance.client.auth.currentSession != null;
  String text(String hindi, String english) => isHindi ? hindi : english;
  bool isBusy(String postId) => _busy.contains(postId);
  bool isSaved(String postId) => _bookmarks.contains(postId);
  Set<String> get savedIds => Set.unmodifiable(_bookmarks);
  CommunityPost? cachedPost(String id) => _cache[id];
  FeedQuery get query => FeedQuery(
    location: selectedLocation!,
    scope: scope,
    sort: sort,
    type: filter?.key,
    search: search,
  );

  void _emit() {
    if (!_disposed) notifyListeners();
  }

  String get _settingsKey => 'mohalla.saved.${profile?.id ?? 'guest'}';

  Future<void> initialize() async {
    isHindi = preferences?.getBool('mohalla.hindi') ?? false;
    await reloadSession();
  }

  Future<void> reloadSession() async {
    _generation++;
    loading = true;
    error = null;
    _emit();
    try {
      await repository.initialize();
      _cache.clear();
      posts = [];
      _bookmarks.clear();
      _cursor = null;
      _bookmarks.addAll(preferences?.getStringList(_settingsKey) ?? []);
      if (hasSession) {
        final location = profile?.location;
        await locationsFor(location?.district ?? 'Patna');
        selectedLocation = location;
      } else {
        selectedLocation = null;
      }
      initialized = true;
      if (selectedLocation != null) await refresh();
    } catch (e) {
      error = friendlyError(e);
      initialized = true;
    } finally {
      loading = false;
      _emit();
    }
  }

  Future<List<AreaPath>> locationsFor(String district) async {
    if (_catalogue.containsKey(district)) return _catalogue[district]!;
    final result = await repository.getLocations(district: district);
    _catalogue[district] = result;
    return result;
  }

  Future<void> toggleLanguage() async {
    isHindi = !isHindi;
    _emit();
    await preferences?.setBool('mohalla.hindi', isHindi);
  }

  void setTab(int value) {
    tab = value;
    _emit();
  }

  Future<void> selectLocation(AreaPath location) async {
    selectedLocation = location;
    scope = FeedScope.ward;
    search = '';
    _emit();
    await refresh();
  }

  Future<void> setScope(FeedScope value) async {
    scope = value;
    await refresh();
  }

  Future<void> setFilter(PostType? value) async {
    filter = value;
    await refresh();
  }

  Future<void> setSort(FeedSort value) async {
    sort = value;
    await refresh();
  }

  Future<void> setSearch(String value) async {
    search = value;
    await refresh();
  }

  Future<void> refresh() async {
    if (selectedLocation == null) return;
    final generation = ++_generation;
    final q = query;
    final key =
        '${q.location.identity}|${q.scope.name}|${q.type}|${q.search}|${q.sort.name}';
    if (_activeQuery != key) {
      posts = [];
      stats = const CommunityStats();
      _activeQuery = key;
    }
    loading = true;
    loadingMore = false;
    error = null;
    _cursor = null;
    _emit();
    try {
      // Both requests are awaited even if one fails (no unhandled async errors).
      final results = await Future.wait<Object>([
        repository.getFeed(q),
        repository.getStats(q.location),
      ]);
      if (generation != _generation || _disposed) return;
      final page = results[0] as FeedPage;
      stats = results[1] as CommunityStats;
      posts = page.posts;
      _cursor = page.nextCursor;
      for (final p in posts) {
        _cache[p.id] = p;
      }
    } catch (e) {
      if (generation == _generation) error = friendlyError(e);
    } finally {
      if (generation == _generation) {
        loading = false;
        _emit();
      }
    }
  }

  Future<void> loadMore() async {
    if (_cursor == null || loading || loadingMore) return;
    final generation = _generation;
    loadingMore = true;
    _emit();
    try {
      final page = await repository.getFeed(query, cursor: _cursor);
      if (generation != _generation || _disposed) return;
      final ids = posts.map((p) => p.id).toSet();
      posts = [...posts, ...page.posts.where((p) => !ids.contains(p.id))];
      _cursor = page.nextCursor;
      for (final p in page.posts) {
        _cache[p.id] = p;
      }
    } catch (e) {
      if (generation == _generation) error = friendlyError(e);
    } finally {
      if (generation == _generation) {
        loadingMore = false;
        _emit();
      }
    }
  }

  void _replace(CommunityPost post) {
    _cache[post.id] = post;
    posts = posts.map((p) => p.id == post.id ? post : p).toList();
    _emit();
  }

  Future<CommunityPost?> fetchPost(String id) async {
    final p = await repository.getPost(id);
    if (p != null) _replace(p);
    return p;
  }

  Future<void> toggleReaction(CommunityPost p, ReactionType type) async {
    if (_busy.contains(p.id)) return;
    final current = _cache[p.id] ?? p;
    _busy.add(p.id);
    _emit();
    try {
      final updated = await repository.setReaction(
        p.id,
        type,
        !current.myReactions.contains(type),
      );
      _replace(updated);
    } finally {
      _busy.remove(p.id);
      _emit();
    }
  }

  Future<void> toggleSaved(String id) async {
    final wasSaved = isSaved(id);
    wasSaved ? _bookmarks.remove(id) : _bookmarks.add(id);
    _emit();
    try {
      final success = await preferences?.setStringList(
        _settingsKey,
        _bookmarks.toList(),
      );
      if (success == false) {
        throw StateError('Unable to save bookmark. Local storage is full.');
      }
    } catch (_) {
      wasSaved ? _bookmarks.add(id) : _bookmarks.remove(id);
      _emit();
      rethrow;
    }
  }

  Future<List<CommunityPost>> savedPosts() async {
    final results = await Future.wait(
      _bookmarks.map((id) => repository.getPost(id)),
    );
    return results.whereType<CommunityPost>().toList()
      ..sort((a, b) => b.createdAt.compareTo(a.createdAt));
  }

  Future<CommunityPost> publish(PostDraft draft) async {
    final p = await repository.publish(draft);
    if (!selectedLocation!.contains(p.location, scope)) {
      selectedLocation = p.location;
    }
    filter = null;
    search = '';
    tab = 0;
    await refresh();
    _replace(p);
    return p;
  }

  Future<List<ThreadComment>> comments(String id) => repository.getComments(id);
  Future<ThreadComment> addComment(
    String id,
    String content, {
    String? parentId,
  }) async {
    final c = await repository.addComment(id, content, parentId: parentId);
    await fetchPost(id);
    return c;
  }

  Future<void> resolve(CommunityPost p, bool value) async {
    if (_busy.contains(p.id)) return;
    _busy.add(p.id);
    _emit();
    try {
      _replace(await repository.setResolved(p.id, value));
    } finally {
      _busy.remove(p.id);
      _emit();
    }
    stats = await repository.getStats(selectedLocation!);
    _emit();
  }

  Future<void> report(CommunityPost p, String reason) async {
    await repository.report(p.id, reason);
    final updated = await repository.getPost(p.id);
    if (updated != null) {
      _replace(updated);
    } else {
      posts = posts.where((e) => e.id != p.id).toList();
      _cache.remove(p.id);
      _emit();
    }
  }

  Future<void> deletePost(String id) async {
    await repository.deletePost(id);
    _cache.remove(id);
    _bookmarks.remove(id);
    await preferences?.setStringList(_settingsKey, _bookmarks.toList());
    await refresh();
  }

  Future<void> saveProfile(
    String name,
    AreaPath location,
    String landmark,
  ) async {
    await repository.updateProfile(name, location, landmark);
    selectedLocation = location;
    scope = FeedScope.ward;
    await refresh();
    _emit();
  }

  Future<void> signOut() async {
    await repository.signOut();
    await reloadSession();
  }

  /// Google Play account-deletion flow: server wipes every trace of the
  /// caller; afterwards a fresh anonymous guest can re-onboard.
  Future<void> deleteAccount() async {
    await repository.deleteAccount();
    await reloadSession();
  }

  static String friendlyError(Object error) {
    if (error is PostgrestException) {
      if (error.message.contains('rate_limit')) {
        return 'A little too fast. Please wait before trying again.';
      }
      if (error.message.contains('not_authenticated')) {
        return 'Your session expired. Please sign in again.';
      }
      return error.message.length > 220
          ? 'Unable to complete this request. Please try again.'
          : error.message;
    }
    if (error is AuthException) return error.message;
    if (error is ArgumentError) return '${error.message}';
    if (error is StateError) return error.message;
    return 'Could not connect. Check your internet connection and try again.';
  }

  @override
  void dispose() {
    _disposed = true;
    _generation++;
    super.dispose();
  }
}
