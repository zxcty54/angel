import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../controllers/app_controller.dart';
import '../../models/community.dart';
import '../../theme/app_theme.dart';
import '../widgets/common.dart';
import '../widgets/post_card.dart';

class PostDetailScreen extends StatefulWidget {
  const PostDetailScreen({super.key, required this.post});
  final CommunityPost post;
  @override
  State<PostDetailScreen> createState() => _PostDetailScreenState();
}

class _PostDetailScreenState extends State<PostDetailScreen> {
  final _message = TextEditingController();
  final _focus = FocusNode();
  final _commentsAnchor = GlobalKey();
  Future<List<ThreadComment>>? _future;
  ThreadComment? _replyTo;
  bool _sending = false;
  bool _missing = false;
  @override
  void initState() {
    super.initState();
    _future = _load();
  }

  Future<List<ThreadComment>> _load() async {
    final c = context.read<AppController>();
    final result = await Future.wait<Object?>([
      c.comments(widget.post.id),
      c.fetchPost(widget.post.id),
    ]);
    if (result[1] == null && mounted) setState(() => _missing = true);
    return result[0] as List<ThreadComment>;
  }

  @override
  void dispose() {
    _message.dispose();
    _focus.dispose();
    super.dispose();
  }

  Future<void> _send() async {
    final text = _message.text.trim();
    if (text.isEmpty || _sending) return;
    setState(() => _sending = true);
    try {
      await context.read<AppController>().addComment(
        widget.post.id,
        text,
        parentId: _replyTo?.id,
      );
      if (!mounted) return;
      _message.clear();
      _focus.unfocus();
      setState(() {
        _replyTo = null;
        _future = _load();
      });
    } catch (e) {
      if (mounted) notifyUser(context, AppController.friendlyError(e));
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  void _startReply(ThreadComment comment) {
    setState(() => _replyTo = comment);
    _focus.requestFocus();
  }

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    final p = c.cachedPost(widget.post.id) ?? widget.post;
    return Scaffold(
      appBar: AppBar(
        title: Text(
          c.text('मोहल्ले की बातचीत', 'A neighbourhood conversation'),
          style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w800),
        ),
      ),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 720),
          child: _missing
              ? Padding(
                  padding: const EdgeInsets.all(24),
                  child: EmptyState(
                    title: c.text(
                      'यह पोस्ट उपलब्ध नहीं है',
                      'This post is no longer available',
                    ),
                    message: c.text(
                      'पोस्ट हटाई गई या community review के लिए छिपाई गई है।',
                      'It may have been deleted or hidden for community review.',
                    ),
                    icon: Icons.visibility_off_outlined,
                  ),
                )
              : ListView(
                  padding: const EdgeInsets.fromLTRB(18, 18, 18, 28),
                  keyboardDismissBehavior:
                      ScrollViewKeyboardDismissBehavior.onDrag,
                  children: [
                    PostCard(
                      post: p,
                      expanded: true,
                      onDeleted: () {
                        if (mounted) Navigator.pop(context);
                      },
                      onOpen: () {
                        final anchor = _commentsAnchor.currentContext;
                        if (anchor != null) {
                          Scrollable.ensureVisible(
                            anchor,
                            duration: const Duration(milliseconds: 300),
                            alignment: .1,
                          );
                        }
                      },
                    ),
                    const SizedBox(height: 22),
                    Container(
                      key: _commentsAnchor,
                      padding: const EdgeInsets.all(18),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(18),
                        border: Border.all(color: MCColors.border),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              const Icon(
                                Icons.forum_outlined,
                                color: MCColors.green,
                                size: 20,
                              ),
                              const SizedBox(width: 10),
                              Text(
                                c.text(
                                  'बातचीत · ${p.commentCount}',
                                  'Conversation · ${p.commentCount}',
                                ),
                                style: const TextStyle(
                                  fontSize: 17,
                                  fontWeight: FontWeight.w800,
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 5),
                          Text(
                            c.text(
                              'राय साझा करें, मदद करें, सम्मान बनाए रखें।',
                              'Share a thought. Offer a hand. Be respectful.',
                            ),
                            style: const TextStyle(
                              fontSize: 11,
                              color: MCColors.muted,
                            ),
                          ),
                          const SizedBox(height: 18),
                          FutureBuilder<List<ThreadComment>>(
                            future: _future,
                            builder: (context, snapshot) {
                              if (snapshot.hasError) {
                                return EmptyState(
                                  title: c.text(
                                    'जवाब लोड नहीं हुए',
                                    'Could not load replies',
                                  ),
                                  message: AppController.friendlyError(
                                    snapshot.error!,
                                  ),
                                  action: () =>
                                      setState(() => _future = _load()),
                                  actionLabel: c.text('फिर कोशिश', 'Retry'),
                                );
                              }
                              if (!snapshot.hasData) {
                                return const Center(
                                  child: Padding(
                                    padding: EdgeInsets.all(20),
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                    ),
                                  ),
                                );
                              }
                              final comments = snapshot.data!;
                              if (comments.isEmpty) {
                                return Padding(
                                  padding: const EdgeInsets.symmetric(
                                    vertical: 16,
                                  ),
                                  child: Text(
                                    c.text(
                                      'पहला जवाब आपका हो सकता है।',
                                      'Your voice could be the first reply.',
                                    ),
                                    style: const TextStyle(
                                      color: MCColors.muted,
                                      fontSize: 12,
                                    ),
                                  ),
                                );
                              }
                              return Column(children: _thread(comments));
                            },
                          ),
                          const SizedBox(height: 14),
                          if (_replyTo != null)
                            Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 12,
                                vertical: 5,
                              ),
                              decoration: BoxDecoration(
                                color: MCColors.greenSoft,
                                borderRadius: BorderRadius.circular(10),
                              ),
                              child: Row(
                                children: [
                                  Expanded(
                                    child: Text(
                                      c.text(
                                        '${_replyTo!.author.name} को जवाब',
                                        'Replying to ${_replyTo!.author.name}',
                                      ),
                                      style: const TextStyle(
                                        fontSize: 11,
                                        color: MCColors.green,
                                      ),
                                    ),
                                  ),
                                  IconButton(
                                    onPressed: () =>
                                        setState(() => _replyTo = null),
                                    icon: const Icon(Icons.close, size: 15),
                                    tooltip: c.text(
                                      'जवाब रद्द करें',
                                      'Cancel reply',
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          const SizedBox(height: 10),
                          TextField(
                            controller: _message,
                            focusNode: _focus,
                            enabled: !_sending,
                            maxLength: 2000,
                            minLines: 2,
                            maxLines: 5,
                            decoration: InputDecoration(
                              hintText: c.text(
                                'अपनी बात लिखें…',
                                'Add your voice…',
                              ),
                            ),
                            style: const TextStyle(fontSize: 12, height: 1.6),
                            onChanged: (_) => setState(() {}),
                          ),
                          const SizedBox(height: 7),
                          Row(
                            children: [
                              ProfileAvatar(c.profile!, size: 28),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  c.text(
                                    'एक अच्छे पड़ोसी की तरह लिखें।',
                                    'Write like a good neighbour.',
                                  ),
                                  style: const TextStyle(
                                    color: MCColors.muted,
                                    fontSize: 10,
                                  ),
                                ),
                              ),
                              FilledButton.icon(
                                onPressed:
                                    _sending || _message.text.trim().isEmpty
                                    ? null
                                    : _send,
                                style: FilledButton.styleFrom(
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 15,
                                    vertical: 10,
                                  ),
                                ),
                                icon: _sending
                                    ? const SizedBox(
                                        width: 14,
                                        height: 14,
                                        child: CircularProgressIndicator(
                                          strokeWidth: 2,
                                        ),
                                      )
                                    : const Icon(Icons.arrow_upward, size: 16),
                                label: Text(
                                  c.text('भेजें', 'Reply'),
                                  style: const TextStyle(fontSize: 11),
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 18),
                    Text(
                      c.text(
                        'जवाबों की गहराई 3 स्तर तक। Live mode में पहले 200 जवाब दिखते हैं।',
                        'Replies support 3 nesting levels. Live mode displays the first 200 replies.',
                      ),
                      textAlign: TextAlign.center,
                      style: const TextStyle(
                        fontSize: 10,
                        color: MCColors.muted,
                      ),
                    ),
                  ],
                ),
        ),
      ),
    );
  }

  List<Widget> _thread(
    List<ThreadComment> comments, {
    String? parent,
    int depth = 0,
  }) {
    if (depth > 3) return [];
    final c = context.read<AppController>();
    return [
      for (final comment in comments.where((e) => e.parentId == parent)) ...[
        Container(
          margin: const EdgeInsets.only(bottom: 12),
          padding: EdgeInsets.only(left: depth == 0 ? 0 : 14),
          decoration: depth == 0
              ? null
              : const BoxDecoration(
                  border: Border(
                    left: BorderSide(color: MCColors.border, width: 2),
                  ),
                ),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              ProfileAvatar(comment.author, size: depth == 0 ? 30 : 25),
              const SizedBox(width: 9),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            comment.author.name,
                            style: const TextStyle(
                              fontSize: 11,
                              fontWeight: FontWeight.w800,
                            ),
                          ),
                        ),
                        Text(
                          relativeTime(context, comment.createdAt),
                          style: const TextStyle(
                            fontSize: 9,
                            color: MCColors.muted,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 5),
                    Text(
                      comment.content,
                      style: const TextStyle(fontSize: 12, height: 1.8),
                    ),
                    if (depth < 3)
                      InkWell(
                        onTap: () => _startReply(comment),
                        child: Padding(
                          padding: const EdgeInsets.symmetric(vertical: 8),
                          child: Text(
                            c.text('जवाब दें', 'Reply'),
                            style: const TextStyle(
                              fontSize: 10,
                              color: MCColors.green,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            ],
          ),
        ),
        ..._thread(comments, parent: comment.id, depth: depth + 1),
      ],
    ];
  }
}
