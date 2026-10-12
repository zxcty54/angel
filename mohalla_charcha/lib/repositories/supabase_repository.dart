import 'dart:typed_data';

import 'package:flutter_image_compress/flutter_image_compress.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'package:uuid/uuid.dart';
import '../models/community.dart';
import '../models/location.dart';
import 'community_repository.dart';

/// Real adapter for the accompanying migration. No service-role privileges.
/// Counts, ownership, metadata validation and moderation are server-controlled.
class SupabaseRepository implements CommunityRepository {
  SupabaseRepository(this.client);
  final SupabaseClient client;
  CommunityProfile? _profile;
  final _signed = <String, ({String url, DateTime expires})>{};
  @override
  bool get isDemo => false;
  @override
  CommunityProfile? get currentProfile => _profile;

  @override
  Future<void> initialize() async {
    if (client.auth.currentUser == null) {
      _profile = null;
      return;
    }
    final row = await client.rpc('bl_get_own_profile');
    _profile = row == null
        ? null
        : CommunityProfile.fromJson(Map<String, dynamic>.from(row as Map));
  }

  @override
  Future<List<AreaPath>> getLocations({String? district}) async {
    if (client.auth.currentUser == null) return [];
    final name = district ?? _profile?.location.district ?? 'Patna';
    final all = <AreaPath>[];
    // Load ONE district at a time, never all Bihar wards on app startup.
    // Supabase defaults to a 1,000-row cap; explicitly paginate the catalogue.
    for (var offset = 0; ; offset += 1000) {
      final rows = await client
          .from('bl_locations')
          .select(
            'id,district,area_type,block_or_ulb,panchayat_name,ward_number,ward_alias,latitude,longitude',
          )
          .eq('district', name)
          .order('id')
          .range(offset, offset + 999);
      all.addAll(rows.map(AreaPath.fromJson));
      if (rows.length < 1000) break;
    }
    return all;
  }

  Future<List<CommunityPost>> _hydrate(List<dynamic> rows) async {
    final data = rows.map((r) => Map<String, dynamic>.from(r as Map)).toList();
    final paths = data
        .expand((j) => List<String>.from(j['media_urls'] as List? ?? []))
        .where((p) => p.isNotEmpty)
        .toSet();
    final pending = paths
        .where(
          (p) =>
              !_signed.containsKey(p) ||
              _signed[p]!.expires.isBefore(DateTime.now()),
        )
        .toList();
    if (pending.isNotEmpty) {
      try {
        final urls = await client.storage
            .from('bl-post-media')
            .createSignedUrlsResult(pending, 3600);
        for (final result in urls) {
          if (result is SignedUrlSuccess) {
            _signed[result.path] = (
              url: result.signedUrl,
              expires: DateTime.now().add(const Duration(minutes: 50)),
            );
          }
        }
      } on StorageException {
        // A missing image must not make a civic discussion inaccessible.
      }
    }
    for (final j in data) {
      j['media_urls'] = List<String>.from(
        j['media_urls'] as List? ?? [],
      ).map((p) => _signed[p]?.url ?? '').toList();
    }
    return data.map(CommunityPost.fromJson).toList();
  }

  @override
  Future<FeedPage> getFeed(FeedQuery q, {FeedCursor? cursor}) async {
    final rows = await client.rpc(
      'bl_get_feed',
      params: {
        'p_location_id': q.location.id,
        'p_scope': q.scope.name,
        'p_type': q.type,
        'p_search': q.search.trim(),
        'p_sort': q.sort.name,
        'p_limit': q.limit + 1,
        'p_cursor_created': cursor?.createdAt.toUtc().toIso8601String(),
        'p_cursor_id': cursor?.id,
        'p_cursor_votes': cursor?.upvotes,
      },
    );
    final posts = await _hydrate(rows as List);
    final hasMore = posts.length > q.limit;
    final visible = posts.take(q.limit).toList();
    return FeedPage(visible, hasMore ? visible.last.cursor : null);
  }

  @override
  Future<CommunityPost?> getPost(String id) async {
    final row = await client.rpc('bl_get_post', params: {'p_post_id': id});
    if (row == null) return null;
    return (await _hydrate([row])).single;
  }

  @override
  Future<List<CommunityPost>> getMyPosts() async {
    final rows = await client.rpc('bl_get_my_posts');
    return _hydrate(rows as List);
  }

  @override
  Future<CommunityPost> publish(PostDraft draft) async {
    draft.validate();
    final uid = client.auth.currentUser?.id;
    if (uid == null || _profile == null) {
      throw StateError(
        'Please wait for your guest session, then finish your profile.',
      );
    }
    final paths = <String>[];
    try {
      for (final bytes in draft.images) {
        // Client-side shrink before upload: free Supabase storage/bandwidth
        // stays small (~0.3 MB/photo instead of 5-12 MB), and JPEG output has
        // no EXIF, so GPS/camera metadata never leaves the phone.
        final Uint8List compressed;
        try {
          compressed = await FlutterImageCompress.compressWithList(
            bytes,
            minWidth: 1280,
            minHeight: 1280,
            quality: 78,
            format: CompressFormat.jpeg,
            keepExif: false,
          );
        } catch (_) {
          throw ArgumentError('Choose a valid JPEG, PNG or WebP image.');
        }
        if (compressed.isEmpty) {
          throw ArgumentError('Choose a valid JPEG, PNG or WebP image.');
        }
        final path = '$uid/${const Uuid().v4()}.jpg';
        await client.storage
            .from('bl-post-media')
            .uploadBinary(
              path,
              compressed,
              fileOptions: FileOptions(
                contentType: 'image/jpeg',
                upsert: false,
              ),
            );
        paths.add(path);
      }
      final id = await client.rpc(
        'bl_create_post',
        params: {
          'p_type': draft.type.key,
          'p_title': draft.title.trim(),
          'p_description': draft.description.trim(),
          'p_location_id': draft.location.id,
          'p_landmark': draft.landmark.trim(),
          'p_metadata': draft.metadata.toJson(),
          'p_media_urls': paths,
          'p_latitude': draft.latitude,
          'p_longitude': draft.longitude,
        },
      );
      final post = await getPost(id as String);
      if (post == null) {
        throw StateError('Post was created. Refresh the feed to see it.');
      }
      return post;
    } catch (_) {
      // Remove uploads only if not attached. Storage DELETE policy enforces this.
      if (paths.isNotEmpty) {
        try {
          await client.storage.from('bl-post-media').remove(paths);
        } on StorageException {
          /* Scheduled orphan cleanup handles interrupted clients. */
        }
      }
      rethrow;
    }
  }

  @override
  Future<CommunityPost> setReaction(
    String postId,
    ReactionType type,
    bool active,
  ) async {
    await client.rpc(
      'bl_set_reaction',
      params: {'p_post_id': postId, 'p_reaction': type.key, 'p_active': active},
    );
    final p = await getPost(postId);
    if (p == null) throw StateError('Post is no longer available.');
    return p;
  }

  @override
  Future<List<ThreadComment>> getComments(String postId) async {
    final rows = await client.rpc(
      'bl_get_comments',
      params: {'p_post_id': postId},
    );
    return (rows as List)
        .map((r) => ThreadComment.fromJson(Map<String, dynamic>.from(r as Map)))
        .toList();
  }

  @override
  Future<ThreadComment> addComment(
    String postId,
    String content, {
    String? parentId,
  }) async {
    final row = await client.rpc(
      'bl_add_comment',
      params: {
        'p_post_id': postId,
        'p_content': content.trim(),
        'p_parent_id': parentId,
      },
    );
    return ThreadComment.fromJson(Map<String, dynamic>.from(row as Map));
  }

  @override
  Future<CommunityPost> setResolved(String postId, bool resolved) async {
    await client.rpc(
      'bl_set_issue_resolution',
      params: {'p_post_id': postId, 'p_resolved': resolved},
    );
    final p = await getPost(postId);
    if (p == null) throw StateError('Post is no longer available.');
    return p;
  }

  @override
  Future<void> report(String postId, String reason) async {
    await client.rpc(
      'bl_report_post',
      params: {'p_post_id': postId, 'p_reason': reason},
    );
  }

  @override
  Future<void> deletePost(String postId) async {
    await client.rpc('bl_delete_post', params: {'p_post_id': postId});
  }

  @override
  Future<CommunityProfile> updateProfile(
    String name,
    AreaPath location,
    String landmark,
  ) async {
    final row = await client.rpc(
      'bl_save_profile',
      params: {
        'p_name': name.trim(),
        'p_location_id': location.id,
        'p_landmark': landmark.trim(),
      },
    );
    _profile = CommunityProfile.fromJson(Map<String, dynamic>.from(row as Map));
    return _profile!;
  }

  @override
  Future<CommunityStats> getStats(AreaPath location) async {
    final j = Map<String, dynamic>.from(
      await client.rpc(
            'bl_community_stats',
            params: {'p_location_id': location.id},
          )
          as Map,
    );
    return CommunityStats(
      neighbours: (j['neighbours'] as num).toInt(),
      openIssues: (j['open_issues'] as num).toInt(),
      resolved: (j['resolved'] as num).toInt(),
      events: (j['events'] as num).toInt(),
    );
  }

  @override
  Future<void> signOut() async {
    await client.auth.signOut();
    _profile = null;
    _signed.clear();
  }

  @override
  Future<void> deleteAccount() async {
    // Server-side cascading wipe: profile, posts, comments, reactions,
    // reports, media rows and finally the anonymous auth row itself.
    await client.rpc('bl_delete_my_account');
    await signOut();
  }
}
