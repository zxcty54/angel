import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import '../../controllers/app_controller.dart';
import '../../models/community.dart';
import '../../theme/app_theme.dart';
import 'common.dart';

class PostCard extends StatelessWidget {
  const PostCard({
    super.key,
    required this.post,
    this.onOpen,
    this.expanded = false,
    this.onDeleted,
  });
  final CommunityPost post;
  final VoidCallback? onOpen;
  final bool expanded;
  final VoidCallback? onDeleted;

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    final p = c.cachedPost(post.id) ?? post;
    final upvoted = p.myReactions.contains(ReactionType.upvote);
    final busy = c.isBusy(p.id);
    return Container(
      decoration: BoxDecoration(
        color: MCColors.surface,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: MCColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(18, 17, 10, 0),
            child: Row(
              children: [
                ProfileAvatar(p.author, size: 38),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        p.author.name,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                      const SizedBox(height: 3),
                      Text(
                        '${p.location.shortLabel} · ${relativeTime(context, p.createdAt)}',
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          fontSize: 10,
                          color: MCColors.muted,
                        ),
                      ),
                    ],
                  ),
                ),
                PopupMenuButton<String>(
                  tooltip: c.text('पोस्ट विकल्प', 'Post options'),
                  icon: const Icon(Icons.more_horiz, color: MCColors.muted),
                  onSelected: (value) => _menuAction(context, p, value),
                  itemBuilder: (_) => [
                    PopupMenuItem(
                      value: 'save',
                      child: Text(
                        c.isSaved(p.id)
                            ? c.text('सहेजे से हटाएँ', 'Unsave post')
                            : c.text('पोस्ट सहेजें', 'Save post'),
                      ),
                    ),
                    PopupMenuItem(
                      value: 'copy',
                      child: Text(
                        c.text('पोस्ट का सार कॉपी करें', 'Copy post summary'),
                      ),
                    ),
                    if (p.author.id != c.profile!.id)
                      PopupMenuItem(
                        value: 'report',
                        enabled: !p.reported,
                        child: Text(
                          p.reported
                              ? c.text('रिपोर्ट भेज दी गई', 'Already reported')
                              : c.text('पोस्ट रिपोर्ट करें', 'Report post'),
                        ),
                      ),
                    if (p.author.id == c.profile!.id &&
                        p.type == PostType.civicIssue)
                      PopupMenuItem(
                        value: 'resolve',
                        child: Text(
                          p.isResolved
                              ? c.text('मुद्दा फिर खोलें', 'Reopen issue')
                              : c.text(
                                  'हल हो गया चिह्नित करें',
                                  'Mark as resolved',
                                ),
                        ),
                      ),
                    if (p.author.id == c.profile!.id)
                      PopupMenuItem(
                        value: 'delete',
                        child: Text(
                          c.text('पोस्ट हटाएँ', 'Delete post'),
                          style: const TextStyle(color: MCColors.primary),
                        ),
                      ),
                  ],
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(18, 13, 18, 0),
            child: Wrap(
              spacing: 8,
              runSpacing: 7,
              children: [
                LabelPill(
                  text: p.type.label(context),
                  color: p.type.color,
                  background: p.type.softColor,
                  icon: p.type.icon,
                  small: true,
                ),
                if (p.isResolved)
                  LabelPill(
                    text: c.text('सुलझा हुआ', 'Resolved'),
                    icon: Icons.check_circle_outline,
                    small: true,
                  ),
                if (p.metadata is IssueMetadata &&
                    (p.metadata as IssueMetadata).severity == Severity.high &&
                    !p.isResolved)
                  LabelPill(
                    text: c.text('ज़्यादा असर', 'High impact'),
                    color: MCColors.primary,
                    background: MCColors.primarySoft,
                    small: true,
                  ),
              ],
            ),
          ),
          InkWell(
            onTap: onOpen,
            borderRadius: BorderRadius.circular(16),
            child: Padding(
              padding: const EdgeInsets.fromLTRB(18, 13, 18, 12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    p.title,
                    style: TextStyle(
                      fontSize: expanded ? 23 : 17,
                      fontWeight: FontWeight.w800,
                      height: 1.55,
                      letterSpacing: expanded ? -.4 : -.15,
                    ),
                  ),
                  const SizedBox(height: 7),
                  Text(
                    p.description,
                    maxLines: expanded ? null : 2,
                    overflow: expanded ? null : TextOverflow.ellipsis,
                    style: const TextStyle(
                      fontSize: 12,
                      color: MCColors.muted,
                      height: 1.8,
                    ),
                  ),
                ],
              ),
            ),
          ),
          if (p.mediaUrls.isNotEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 18),
              child: GestureDetector(
                onTap: expanded
                    ? () => _showPhotos(context, p.mediaUrls)
                    : onOpen,
                child: Stack(
                  children: [
                    ClipRRect(
                      borderRadius: BorderRadius.circular(12),
                      child: CommunityImage(
                        p.mediaUrls.first,
                        height: expanded ? 260 : 174,
                      ),
                    ),
                    if (p.mediaUrls.length > 1)
                      Positioned(
                        right: 10,
                        bottom: 10,
                        child: Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 9,
                            vertical: 5,
                          ),
                          decoration: BoxDecoration(
                            color: MCColors.ink.withValues(alpha: .8),
                            borderRadius: BorderRadius.circular(7),
                          ),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              const Icon(
                                Icons.photo_library_outlined,
                                size: 13,
                                color: Colors.white,
                              ),
                              const SizedBox(width: 5),
                              Text(
                                '${p.mediaUrls.length}',
                                style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 11,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            ),
          if (p.metadata is ReviewMetadata)
            Padding(
              padding: const EdgeInsets.fromLTRB(18, 12, 18, 0),
              child: _ReviewInfo(p.metadata as ReviewMetadata),
            ),
          if (p.metadata is EventMetadata)
            Padding(
              padding: const EdgeInsets.fromLTRB(18, 4, 18, 0),
              child: _EventInfo(p.metadata as EventMetadata),
            ),
          if (p.landmark.isNotEmpty)
            Padding(
              padding: const EdgeInsets.fromLTRB(18, 12, 18, 0),
              child: Row(
                children: [
                  const Icon(
                    Icons.location_on_outlined,
                    size: 13,
                    color: MCColors.muted,
                  ),
                  const SizedBox(width: 5),
                  Expanded(
                    child: Text(
                      p.landmark,
                      style: const TextStyle(
                        fontSize: 10,
                        color: MCColors.muted,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  Text(
                    'Ward ${p.location.ward}',
                    style: const TextStyle(fontSize: 10, color: MCColors.muted),
                  ),
                ],
              ),
            ),
          Padding(
            padding: const EdgeInsets.fromLTRB(18, 13, 18, 0),
            child: Row(
              children: [
                Semantics(
                  button: true,
                  label: c.text(
                    'समर्थन दें, ${p.upvotes} समर्थन',
                    'Upvote, ${p.upvotes} votes',
                  ),
                  selected: upvoted,
                  child: InkWell(
                    onTap: busy
                        ? null
                        : () => safeAction(
                            context,
                            () => c.toggleReaction(p, ReactionType.upvote),
                          ),
                    borderRadius: BorderRadius.circular(10),
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 9,
                      ),
                      decoration: BoxDecoration(
                        color: upvoted
                            ? MCColors.primarySoft
                            : MCColors.background,
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(
                          color: upvoted
                              ? MCColors.primary.withValues(alpha: .2)
                              : MCColors.border,
                        ),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            upvoted
                                ? Icons.arrow_upward_rounded
                                : Icons.arrow_upward,
                            size: 17,
                            color: upvoted ? MCColors.primary : MCColors.ink,
                          ),
                          const SizedBox(width: 7),
                          Text(
                            '${p.upvotes}',
                            style: TextStyle(
                              fontSize: 12,
                              fontWeight: FontWeight.w800,
                              color: upvoted ? MCColors.primary : MCColors.ink,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                TextButton.icon(
                  onPressed: onOpen,
                  icon: const Icon(Icons.chat_bubble_outline_rounded, size: 16),
                  label: Text(
                    '${p.commentCount}',
                    style: const TextStyle(fontSize: 12),
                  ),
                  style: TextButton.styleFrom(
                    foregroundColor: MCColors.muted,
                    padding: const EdgeInsets.symmetric(horizontal: 10),
                  ),
                ),
                const Spacer(),
                IconButton(
                  onPressed: () =>
                      safeAction(context, () => c.toggleSaved(p.id)),
                  icon: Icon(
                    c.isSaved(p.id)
                        ? Icons.bookmark_rounded
                        : Icons.bookmark_border_rounded,
                    size: 20,
                    color: c.isSaved(p.id) ? MCColors.primary : MCColors.muted,
                  ),
                  tooltip: c.text(
                    c.isSaved(p.id) ? 'सहेजे से हटाएँ' : 'सहेजें',
                    c.isSaved(p.id) ? 'Unsave' : 'Save',
                  ),
                ),
                IconButton(
                  onPressed: () => _menuAction(context, p, 'copy'),
                  icon: const Icon(
                    Icons.ios_share_rounded,
                    size: 18,
                    color: MCColors.muted,
                  ),
                  tooltip: c.text('सार कॉपी करें', 'Copy summary'),
                ),
              ],
            ),
          ),
          if (p.metadata is IssueMetadata && !p.isResolved)
            Padding(
              padding: const EdgeInsets.fromLTRB(18, 8, 18, 16),
              child: _SpecialAction(
                icon: Icons.people_outline,
                color: MCColors.primary,
                soft: MCColors.primarySoft,
                active: p.myReactions.contains(ReactionType.ditto),
                busy: busy,
                text: p.myReactions.contains(ReactionType.ditto)
                    ? c.text(
                        'आपके यहाँ भी · ${(p.metadata as IssueMetadata).dittoCount}',
                        'You too · ${(p.metadata as IssueMetadata).dittoCount}',
                      )
                    : c.text(
                        'मेरे यहाँ भी · ${(p.metadata as IssueMetadata).dittoCount}',
                        'Same here · ${(p.metadata as IssueMetadata).dittoCount}',
                      ),
                onTap: () => safeAction(
                  context,
                  () => c.toggleReaction(p, ReactionType.ditto),
                ),
              ),
            ),
          if (p.metadata is EventMetadata)
            Padding(
              padding: const EdgeInsets.fromLTRB(18, 8, 18, 16),
              child: _SpecialAction(
                icon: p.myReactions.contains(ReactionType.rsvp)
                    ? Icons.check_circle_outline
                    : Icons.event_available_outlined,
                color: MCColors.green,
                soft: MCColors.greenSoft,
                active: p.myReactions.contains(ReactionType.rsvp),
                busy: busy || (p.metadata as EventMetadata).hasEnded,
                text: (p.metadata as EventMetadata).hasEnded
                    ? c.text('कार्यक्रम समाप्त', 'Event ended')
                    : c.text(
                        '${p.myReactions.contains(ReactionType.rsvp) ? 'आप आ रहे हैं' : 'मैं भी आऊँगा/आऊँगी'} · ${(p.metadata as EventMetadata).rsvpCount}',
                        '${p.myReactions.contains(ReactionType.rsvp) ? 'You’re going' : 'Count me in'} · ${(p.metadata as EventMetadata).rsvpCount}',
                      ),
                onTap: () => safeAction(
                  context,
                  () => c.toggleReaction(p, ReactionType.rsvp),
                ),
              ),
            ),
          if (p.isResolved)
            Padding(
              padding: const EdgeInsets.fromLTRB(18, 8, 18, 16),
              child: Row(
                children: [
                  const Icon(
                    Icons.volunteer_activism_outlined,
                    size: 16,
                    color: MCColors.green,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      c.text(
                        'पड़ोसियों की पहल से बदलाव आया।',
                        'A little teamwork made a difference.',
                      ),
                      style: const TextStyle(
                        fontSize: 11,
                        color: MCColors.green,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          if (p.type == PostType.localReview || p.type == PostType.general)
            const SizedBox(height: 13),
        ],
      ),
    );
  }

  Future<void> _menuAction(
    BuildContext context,
    CommunityPost p,
    String value,
  ) async {
    final c = context.read<AppController>();
    switch (value) {
      case 'save':
        await safeAction(context, () => c.toggleSaved(p.id));
      case 'copy':
        await safeAction(context, () async {
          await Clipboard.setData(
            ClipboardData(
              text:
                  '${p.title}\n\n${p.description}\n\n${p.location.fullLabel}\n— Mohalla Charcha (P2P community)',
            ),
          );
          if (context.mounted) {
            notifyUser(
              context,
              c.text('पोस्ट का सार कॉपी हो गया', 'Post summary copied'),
            );
          }
        });
      case 'report':
        await reportPostDialog(context, p);
      case 'resolve':
        await safeAction(context, () => c.resolve(p, !p.isResolved));
      case 'delete':
        final yes = await showDialog<bool>(
          context: context,
          builder: (dialogContext) => AlertDialog(
            title: Text(c.text('यह पोस्ट हटाएँ?', 'Delete this post?')),
            content: Text(
              c.text(
                'पोस्ट और उसके जवाब हमेशा के लिए हट जाएँगे।',
                'This permanently removes the post and its replies.',
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(dialogContext, false),
                child: Text(c.text('रहने दें', 'Cancel')),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(dialogContext, true),
                child: Text(c.text('हटाएँ', 'Delete')),
              ),
            ],
          ),
        );
        if (yes == true && context.mounted) {
          await safeAction(context, () async {
            await c.deletePost(p.id);
            onDeleted?.call();
          });
        }
    }
  }
}

class _SpecialAction extends StatelessWidget {
  const _SpecialAction({
    required this.icon,
    required this.color,
    required this.soft,
    required this.text,
    required this.active,
    required this.busy,
    required this.onTap,
  });
  final IconData icon;
  final Color color;
  final Color soft;
  final String text;
  final bool active;
  final bool busy;
  final VoidCallback onTap;
  @override
  Widget build(BuildContext context) => SizedBox(
    width: double.infinity,
    child: OutlinedButton.icon(
      onPressed: busy ? null : onTap,
      style: OutlinedButton.styleFrom(
        backgroundColor: active ? soft : Colors.transparent,
        foregroundColor: color,
        side: BorderSide(color: color.withValues(alpha: .23)),
        padding: const EdgeInsets.symmetric(vertical: 11),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      ),
      icon: Icon(active ? Icons.check : icon, size: 17),
      label: Text(
        text,
        style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w700),
      ),
    ),
  );
}

class _ReviewInfo extends StatelessWidget {
  const _ReviewInfo(this.meta);
  final ReviewMetadata meta;
  @override
  Widget build(BuildContext context) => Row(
    children: [
      const Icon(Icons.storefront_outlined, size: 17, color: MCColors.amber),
      const SizedBox(width: 6),
      Expanded(
        child: Text(
          meta.businessName,
          style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w700),
        ),
      ),
      const Icon(Icons.star_rounded, size: 17, color: MCColors.amber),
      const SizedBox(width: 4),
      Text(
        meta.rating.toStringAsFixed(1),
        style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w800),
      ),
      const Text(' / 5', style: TextStyle(color: MCColors.muted, fontSize: 10)),
    ],
  );
}

class _EventInfo extends StatelessWidget {
  const _EventInfo(this.meta);
  final EventMetadata meta;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(
      color: MCColors.greenSoft,
      borderRadius: BorderRadius.circular(12),
    ),
    child: Row(
      children: [
        const Icon(
          Icons.calendar_month_outlined,
          size: 23,
          color: MCColors.green,
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                eventDate(context, meta.date),
                style: const TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w800,
                  color: MCColors.green,
                ),
              ),
              const SizedBox(height: 3),
              Text(
                meta.venue,
                style: const TextStyle(fontSize: 10, color: MCColors.green),
                overflow: TextOverflow.ellipsis,
              ),
            ],
          ),
        ),
      ],
    ),
  );
}

Future<void> reportPostDialog(BuildContext context, CommunityPost post) async {
  final c = context.read<AppController>();
  final reason = await showModalBottomSheet<String>(
    context: context,
    useSafeArea: true,
    constraints: const BoxConstraints(maxWidth: 520),
    builder: (sheet) => Padding(
      padding: const EdgeInsets.fromLTRB(24, 0, 24, 26),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            c.text('समुदाय को सुरक्षित रखें', 'Keep the community safe'),
            style: const TextStyle(fontSize: 21, fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 8),
          Text(
            c.text(
              'यह community moderation के लिए है, सरकारी शिकायत नहीं।',
              'Reports are for community moderation, not government complaints.',
            ),
            style: const TextStyle(
              fontSize: 12,
              color: MCColors.muted,
              height: 1.6,
            ),
          ),
          const SizedBox(height: 14),
          for (final r in [
            ('spam', 'स्पैम / विज्ञापन', 'Spam or advertising'),
            ('abuse', 'नफ़रत / उत्पीड़न', 'Hate or harassment'),
            (
              'privacy',
              'निजी जानकारी साझा करना',
              'Exposes private information',
            ),
            (
              'misleading',
              'भ्रामक या असुरक्षित सामग्री',
              'Misleading or unsafe content',
            ),
          ])
            ListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(
                c.text(r.$2, r.$3),
                style: const TextStyle(fontSize: 13),
              ),
              trailing: const Icon(Icons.chevron_right, size: 18),
              onTap: () => Navigator.pop(sheet, r.$1),
            ),
        ],
      ),
    ),
  );
  if (reason != null && context.mounted) {
    await safeAction(context, () async {
      await c.report(post, reason);
      if (context.mounted) {
        notifyUser(
          context,
          c.text(
            'धन्यवाद। रिपोर्ट community review के लिए दर्ज हुई।',
            'Thank you. Your report is recorded for community review.',
          ),
        );
      }
    });
  }
}

void _showPhotos(BuildContext context, List<String> urls) => showDialog<void>(
  context: context,
  builder: (dialog) => Dialog(
    backgroundColor: MCColors.ink,
    insetPadding: const EdgeInsets.all(18),
    child: SizedBox(
      width: 900,
      height: MediaQuery.sizeOf(context).height * .8,
      child: Stack(
        children: [
          PageView(
            children: urls
                .map(
                  (u) => Center(
                    child: CommunityImage(
                      u,
                      height: MediaQuery.sizeOf(context).height * .7,
                      fit: BoxFit.contain,
                    ),
                  ),
                )
                .toList(),
          ),
          Positioned(
            top: 8,
            right: 8,
            child: IconButton(
              onPressed: () => Navigator.pop(dialog),
              icon: const Icon(Icons.close, color: Colors.white),
            ),
          ),
          if (urls.length > 1)
            Positioned(
              bottom: 16,
              left: 20,
              child: Text(
                tr(
                  context,
                  'बाकी फ़ोटो के लिए स्वाइप करें',
                  'Swipe for more photos',
                ),
                style: const TextStyle(color: Colors.white, fontSize: 12),
              ),
            ),
        ],
      ),
    ),
  ),
);
