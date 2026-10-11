import '../models/community.dart';
import '../models/location.dart';

/// UI depends on this interface. Switching backends never changes screens.
abstract class CommunityRepository {
  bool get isDemo;
  CommunityProfile? get currentProfile;
  Future<void> initialize();
  Future<List<AreaPath>> getLocations({String? district});
  Future<FeedPage> getFeed(FeedQuery query, {FeedCursor? cursor});
  Future<CommunityPost?> getPost(String id);
  Future<List<CommunityPost>> getMyPosts();
  Future<CommunityPost> publish(PostDraft draft);
  Future<CommunityPost> setReaction(
    String postId,
    ReactionType type,
    bool active,
  );
  Future<List<ThreadComment>> getComments(String postId);
  Future<ThreadComment> addComment(
    String postId,
    String content, {
    String? parentId,
  });
  Future<CommunityPost> setResolved(String postId, bool resolved);
  Future<void> report(String postId, String reason);
  Future<void> deletePost(String postId);
  Future<CommunityProfile> updateProfile(
    String name,
    AreaPath location,
    String landmark,
  );
  Future<CommunityStats> getStats(AreaPath location);
  Future<void> signOut();
}
