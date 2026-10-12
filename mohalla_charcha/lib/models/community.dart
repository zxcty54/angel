import 'dart:typed_data';
import 'location.dart';

enum PostType {
  civicIssue('civic_issue'),
  localReview('local_review'),
  event('event'),
  general('general');

  const PostType(this.key);
  final String key;
  static PostType parse(String key) => values.firstWhere((e) => e.key == key);
}

enum ReactionType {
  upvote('upvote'),
  ditto('ditto_problem'),
  rsvp('rsvp_event');

  const ReactionType(this.key);
  final String key;
  static ReactionType parse(String key) =>
      values.firstWhere((e) => e.key == key);
}

enum Severity { low, medium, high }

sealed class PostMetadata {
  const PostMetadata();
  Map<String, dynamic> toJson();

  static PostMetadata parse(PostType type, Map<String, dynamic> data) =>
      switch (type) {
        PostType.civicIssue => IssueMetadata(
          severity: Severity.values.byName(
            (data['severity'] ?? 'medium') as String,
          ),
          resolved: data['is_resolved'] == true,
          dittoCount: (data['ditto_count'] as num?)?.toInt() ?? 0,
        ),
        PostType.localReview => ReviewMetadata(
          businessName: (data['business_name'] ?? '') as String,
          category: (data['category'] ?? 'other') as String,
          rating: (data['rating'] as num?)?.toDouble() ?? 1,
        ),
        PostType.event => EventMetadata(
          date: DateTime.parse(data['event_date'] as String).toUtc(),
          venue: (data['venue'] ?? '') as String,
          rsvpCount: (data['rsvp_count'] as num?)?.toInt() ?? 0,
        ),
        PostType.general => const GeneralMetadata(),
      };
}

final class IssueMetadata extends PostMetadata {
  const IssueMetadata({
    this.severity = Severity.medium,
    this.resolved = false,
    this.dittoCount = 0,
  });
  final Severity severity;
  final bool resolved;
  final int dittoCount;
  @override
  Map<String, dynamic> toJson() => {
    'severity': severity.name,
    'is_resolved': resolved,
    'ditto_count': dittoCount,
  };
  IssueMetadata copyWith({bool? resolved, int? dittoCount}) => IssueMetadata(
    severity: severity,
    resolved: resolved ?? this.resolved,
    dittoCount: dittoCount ?? this.dittoCount,
  );
}

final class ReviewMetadata extends PostMetadata {
  const ReviewMetadata({
    required this.businessName,
    required this.category,
    required this.rating,
  });
  final String businessName;
  final String category;
  final double rating;
  @override
  Map<String, dynamic> toJson() => {
    'business_name': businessName,
    'category': category,
    'rating': rating,
  };
}

final class EventMetadata extends PostMetadata {
  const EventMetadata({
    required this.date,
    required this.venue,
    this.rsvpCount = 0,
  });
  final DateTime date;
  final String venue;
  final int rsvpCount;
  bool get hasEnded => date.isBefore(DateTime.now());
  @override
  Map<String, dynamic> toJson() => {
    'event_date': date.toUtc().toIso8601String(),
    'venue': venue,
    'rsvp_count': rsvpCount,
  };
  EventMetadata copyWith({int? rsvpCount}) => EventMetadata(
    date: date,
    venue: venue,
    rsvpCount: rsvpCount ?? this.rsvpCount,
  );
}

final class GeneralMetadata extends PostMetadata {
  const GeneralMetadata();
  @override
  Map<String, dynamic> toJson() => {};
}

class CommunityProfile {
  const CommunityProfile({
    required this.id,
    required this.name,
    required this.location,
    this.landmark = '',
    this.reputation = 0,
    this.avatarUrl,
  });
  final String id;
  final String name;
  final AreaPath location;
  final String landmark;
  final int reputation;
  final String? avatarUrl;
  String get initials => name
      .trim()
      .split(RegExp(r'\s+'))
      .take(2)
      .map((s) => s.isEmpty ? '' : s[0])
      .join();
  CommunityProfile copyWith({
    String? name,
    AreaPath? location,
    String? landmark,
  }) => CommunityProfile(
    id: id,
    name: name ?? this.name,
    location: location ?? this.location,
    landmark: landmark ?? this.landmark,
    reputation: reputation,
    avatarUrl: avatarUrl,
  );
  Map<String, dynamic> toJson() => {
    'id': id,
    'full_name': name,
    'location': location.toJson(),
    'locality_landmark': landmark,
    'reputation_score': reputation,
    'avatar_url': avatarUrl,
  };
  factory CommunityProfile.fromJson(Map<String, dynamic> j) => CommunityProfile(
    id: j['id'] as String,
    name: (j['full_name'] ?? 'Neighbour') as String,
    location: AreaPath.fromJson(
      Map<String, dynamic>.from(j['location'] as Map),
    ),
    landmark: (j['locality_landmark'] ?? '') as String,
    reputation: (j['reputation_score'] as num?)?.toInt() ?? 0,
    avatarUrl: j['avatar_url'] as String?,
  );
}

class CommunityPost {
  const CommunityPost({
    required this.id,
    required this.author,
    required this.type,
    required this.title,
    required this.description,
    required this.location,
    required this.metadata,
    required this.createdAt,
    this.updatedAt,
    this.mediaUrls = const [],
    this.landmark = '',
    this.latitude,
    this.longitude,
    this.upvotes = 0,
    this.commentCount = 0,
    this.flagCount = 0,
    this.hidden = false,
    this.myReactions = const {},
    this.reported = false,
  });
  final String id;
  final CommunityProfile author;
  final PostType type;
  final String title;
  final String description;
  final AreaPath location;
  final PostMetadata metadata;
  final DateTime createdAt;
  final DateTime? updatedAt;
  final List<String> mediaUrls;
  final String landmark;
  final double? latitude;
  final double? longitude;
  final int upvotes;
  final int commentCount;
  final int flagCount;
  final bool hidden;
  final Set<ReactionType> myReactions;
  final bool reported;
  bool get isResolved =>
      metadata is IssueMetadata && (metadata as IssueMetadata).resolved;
  bool get hasCoordinates => latitude != null && longitude != null;
  FeedCursor get cursor => FeedCursor(createdAt, id, upvotes);

  CommunityPost copyWith({
    CommunityProfile? author,
    PostMetadata? metadata,
    int? upvotes,
    int? commentCount,
    int? flagCount,
    bool? hidden,
    Set<ReactionType>? myReactions,
    bool? reported,
    List<String>? mediaUrls,
  }) => CommunityPost(
    id: id,
    author: author ?? this.author,
    type: type,
    title: title,
    description: description,
    location: location,
    metadata: metadata ?? this.metadata,
    createdAt: createdAt,
    updatedAt: DateTime.now().toUtc(),
    mediaUrls: mediaUrls ?? this.mediaUrls,
    landmark: landmark,
    latitude: latitude,
    longitude: longitude,
    upvotes: upvotes ?? this.upvotes,
    commentCount: commentCount ?? this.commentCount,
    flagCount: flagCount ?? this.flagCount,
    hidden: hidden ?? this.hidden,
    myReactions: myReactions ?? this.myReactions,
    reported: reported ?? this.reported,
  );

  Map<String, dynamic> toJson() => {
    'id': id,
    'author': author.toJson(),
    'post_type': type.key,
    'title': title,
    'description': description,
    'location': location.toJson(),
    'metadata': metadata.toJson(),
    'created_at': createdAt.toIso8601String(),
    'updated_at': updatedAt?.toIso8601String(),
    'media_urls': mediaUrls,
    'locality_landmark': landmark,
    'latitude': latitude,
    'longitude': longitude,
    'upvotes_count': upvotes,
    'comments_count': commentCount,
    'flag_count': flagCount,
    'is_hidden': hidden,
    'viewer_reactions': myReactions.map((r) => r.key).toList(),
    'viewer_reported': reported,
  };

  factory CommunityPost.fromJson(Map<String, dynamic> j) {
    final type = PostType.parse(j['post_type'] as String);
    return CommunityPost(
      id: j['id'] as String,
      author: CommunityProfile.fromJson(
        Map<String, dynamic>.from(j['author'] as Map),
      ),
      type: type,
      title: j['title'] as String,
      description: j['description'] as String,
      location: AreaPath.fromJson(
        Map<String, dynamic>.from(j['location'] as Map),
      ),
      metadata: PostMetadata.parse(
        type,
        Map<String, dynamic>.from((j['metadata'] ?? {}) as Map),
      ),
      createdAt: DateTime.parse(j['created_at'] as String).toUtc(),
      updatedAt: j['updated_at'] == null
          ? null
          : DateTime.parse(j['updated_at'] as String).toUtc(),
      mediaUrls: List<String>.from(j['media_urls'] as List? ?? []),
      landmark: (j['locality_landmark'] ?? '') as String,
      latitude: (j['latitude'] as num?)?.toDouble(),
      longitude: (j['longitude'] as num?)?.toDouble(),
      upvotes: (j['upvotes_count'] as num?)?.toInt() ?? 0,
      commentCount: (j['comments_count'] as num?)?.toInt() ?? 0,
      flagCount: (j['flag_count'] as num?)?.toInt() ?? 0,
      hidden: j['is_hidden'] == true,
      myReactions: (j['viewer_reactions'] as List? ?? [])
          .map((r) => ReactionType.parse(r as String))
          .toSet(),
      reported: j['viewer_reported'] == true,
    );
  }
}

class PostDraft {
  const PostDraft({
    required this.type,
    required this.title,
    required this.description,
    required this.location,
    required this.metadata,
    this.landmark = '',
    this.latitude,
    this.longitude,
    this.images = const [],
  });
  final PostType type;
  final String title;
  final String description;
  final AreaPath location;
  final PostMetadata metadata;
  final String landmark;
  final double? latitude;
  final double? longitude;
  final List<Uint8List> images;

  void validate() {
    if (title.trim().length < 5 || title.length > 200) {
      throw ArgumentError('Title must be 5–200 characters.');
    }
    if (description.trim().length < 10 || description.length > 5000) {
      throw ArgumentError('Description must be 10–5000 characters.');
    }
    if (landmark.length > 150) throw ArgumentError('Landmark is too long.');
    if (images.length > 3 ||
        images.any((b) => b.lengthInBytes > 5 * 1024 * 1024)) {
      throw ArgumentError('Up to 3 images, maximum 5 MB each.');
    }
    if ((latitude == null) != (longitude == null)) {
      throw ArgumentError('Both coordinates are required.');
    }
    if (latitude != null &&
        (!latitude!.isFinite ||
            latitude! < -90 ||
            latitude! > 90 ||
            !longitude!.isFinite ||
            longitude! < -180 ||
            longitude! > 180)) {
      throw ArgumentError('Invalid coordinates.');
    }
    final m = metadata;
    if ((type == PostType.civicIssue && m is! IssueMetadata) ||
        (type == PostType.localReview && m is! ReviewMetadata) ||
        (type == PostType.event && m is! EventMetadata) ||
        (type == PostType.general && m is! GeneralMetadata)) {
      throw ArgumentError('Metadata does not match post type.');
    }
    if (m is ReviewMetadata &&
        (m.businessName.trim().isEmpty ||
            m.businessName.length > 120 ||
            m.rating < 1 ||
            m.rating > 5 ||
            !m.rating.isFinite ||
            (m.rating * 2).roundToDouble() != m.rating * 2 ||
            !const {
              'food',
              'grocery',
              'services',
              'health',
              'education',
              'other',
            }.contains(m.category))) {
      throw ArgumentError('Shop name and rating (1–5) are required.');
    }
    if (m is EventMetadata &&
        (m.venue.trim().isEmpty ||
            m.venue.length > 150 ||
            !m.date.isAfter(DateTime.now()))) {
      throw ArgumentError('A future event date and venue are required.');
    }
  }
}

class ThreadComment {
  const ThreadComment({
    required this.id,
    required this.postId,
    required this.author,
    required this.content,
    required this.createdAt,
    this.parentId,
  });
  final String id;
  final String postId;
  final CommunityProfile author;
  final String content;
  final DateTime createdAt;
  final String? parentId;
  Map<String, dynamic> toJson() => {
    'id': id,
    'post_id': postId,
    'author': author.toJson(),
    'content': content,
    'created_at': createdAt.toIso8601String(),
    'parent_comment_id': parentId,
  };
  factory ThreadComment.fromJson(Map<String, dynamic> j) => ThreadComment(
    id: j['id'] as String,
    postId: j['post_id'] as String,
    author: CommunityProfile.fromJson(
      Map<String, dynamic>.from(j['author'] as Map),
    ),
    content: j['content'] as String,
    createdAt: DateTime.parse(j['created_at'] as String).toUtc(),
    parentId: j['parent_comment_id'] as String?,
  );
}

class FeedPage {
  const FeedPage(this.posts, this.nextCursor);
  final List<CommunityPost> posts;
  final FeedCursor? nextCursor;
}

class CommunityStats {
  const CommunityStats({
    this.neighbours = 0,
    this.openIssues = 0,
    this.resolved = 0,
    this.events = 0,
  });
  final int neighbours;
  final int openIssues;
  final int resolved;
  final int events;
}
