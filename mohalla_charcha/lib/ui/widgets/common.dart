import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import '../../controllers/app_controller.dart';
import '../../models/community.dart';
import '../../theme/app_theme.dart';
import '../../config/app_identity.dart';

String tr(BuildContext context, String hi, String en) =>
    context.read<AppController>().text(hi, en);

void notifyUser(BuildContext context, String message) {
  if (!context.mounted) return;
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(message)));
}

Future<void> safeAction(
  BuildContext context,
  Future<void> Function() action,
) async {
  try {
    await action();
  } catch (e) {
    if (context.mounted) notifyUser(context, AppController.friendlyError(e));
  }
}

String relativeTime(BuildContext context, DateTime date) {
  final minutes = DateTime.now().difference(date).inMinutes;
  if (minutes < 1) return tr(context, 'अभी', 'Just now');
  if (minutes < 60) return tr(context, '$minutes मिनट पहले', '${minutes}m ago');
  if (minutes < 1440) {
    return tr(context, '${minutes ~/ 60} घंटे पहले', '${minutes ~/ 60}h ago');
  }
  if (minutes < 10080) {
    return tr(
      context,
      '${minutes ~/ 1440} दिन पहले',
      '${minutes ~/ 1440}d ago',
    );
  }
  return DateFormat(
    'd MMM',
    context.read<AppController>().isHindi ? 'hi' : 'en',
  ).format(date.toLocal());
}

String eventDate(BuildContext context, DateTime date) => DateFormat(
  'EEE, d MMM · h:mm a',
  context.read<AppController>().isHindi ? 'hi' : 'en',
).format(date.toLocal());

extension PostPresentation on PostType {
  IconData get icon => switch (this) {
    PostType.civicIssue => Icons.campaign_outlined,
    PostType.localReview => Icons.storefront_outlined,
    PostType.event => Icons.calendar_month_outlined,
    PostType.general => Icons.forum_outlined,
  };
  Color get color => switch (this) {
    PostType.civicIssue => MCColors.primary,
    PostType.localReview => MCColors.amber,
    PostType.event => MCColors.green,
    PostType.general => MCColors.blue,
  };
  Color get softColor => switch (this) {
    PostType.civicIssue => MCColors.primarySoft,
    PostType.localReview => MCColors.amberSoft,
    PostType.event => MCColors.greenSoft,
    PostType.general => MCColors.blueSoft,
  };
  String label(BuildContext context) => switch (this) {
    PostType.civicIssue => tr(context, 'नागरिक मुद्दा', 'Civic issue'),
    PostType.localReview => tr(context, 'लोकल समीक्षा', 'Local review'),
    PostType.event => tr(context, 'कार्यक्रम', 'Event'),
    PostType.general => tr(context, 'पड़ोस की चर्चा', 'Conversation'),
  };
}

class BrandMark extends StatelessWidget {
  const BrandMark({super.key, this.size = 40});
  final double size;
  @override
  Widget build(BuildContext context) => Semantics(
    label: '${AppIdentity.displayName} logo',
    image: true,
    child: Image.asset(
      'assets/branding/logo.png',
      width: size,
      height: size,
      fit: BoxFit.contain,
      excludeFromSemantics: true,
    ),
  );
}

/// Two-line identity keeps the complete brand legible on narrow screens.
class BrandWordmark extends StatelessWidget {
  const BrandWordmark({super.key, this.titleSize = 19, this.subtitleSize = 9});
  final double titleSize, subtitleSize;
  @override
  Widget build(BuildContext context) => Semantics(
    label: AppIdentity.displayName,
    excludeSemantics: true,
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          AppIdentity.primaryName,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            fontSize: titleSize,
            fontWeight: FontWeight.w800,
            height: 1.2,
          ),
        ),
        const SizedBox(height: 3),
        Text(
          AppIdentity.secondaryName,
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            fontSize: subtitleSize,
            fontWeight: FontWeight.w600,
            height: 1.25,
            color: MCColors.muted,
          ),
        ),
      ],
    ),
  );
}

class ProfileAvatar extends StatelessWidget {
  const ProfileAvatar(this.profile, {super.key, this.size = 40});
  final CommunityProfile profile;
  final double size;
  @override
  Widget build(BuildContext context) {
    final colors = [
      MCColors.primarySoft,
      MCColors.greenSoft,
      MCColors.amberSoft,
      MCColors.blueSoft,
    ];
    final inks = [
      MCColors.primary,
      MCColors.green,
      MCColors.amber,
      MCColors.blue,
    ];
    final n = profile.id.hashCode.abs() % colors.length;
    return Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: colors[n],
        shape: BoxShape.circle,
        border: Border.all(color: Colors.white, width: 2),
      ),
      child: Text(
        profile.initials,
        maxLines: 1,
        style: TextStyle(
          fontSize: size * .29,
          fontWeight: FontWeight.w800,
          color: inks[n],
        ),
      ),
    );
  }
}

class LabelPill extends StatelessWidget {
  const LabelPill({
    super.key,
    required this.text,
    this.color = MCColors.green,
    this.background = MCColors.greenSoft,
    this.icon,
    this.small = false,
  });
  final String text;
  final Color color;
  final Color background;
  final IconData? icon;
  final bool small;
  @override
  Widget build(BuildContext context) => Container(
    padding: EdgeInsets.symmetric(
      horizontal: small ? 8 : 10,
      vertical: small ? 4 : 6,
    ),
    decoration: BoxDecoration(
      color: background,
      borderRadius: BorderRadius.circular(7),
    ),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        if (icon != null) ...[
          Icon(icon, size: small ? 12 : 14, color: color),
          const SizedBox(width: 5),
        ],
        Text(
          text,
          style: TextStyle(
            color: color,
            fontSize: small ? 10 : 11,
            fontWeight: FontWeight.w700,
          ),
        ),
      ],
    ),
  );
}

class CommunityImage extends StatelessWidget {
  const CommunityImage(
    this.source, {
    super.key,
    this.height = 180,
    this.fit = BoxFit.cover,
  });
  final String source;
  final double? height;
  final BoxFit fit;
  @override
  Widget build(BuildContext context) {
    Widget fallback(BuildContext c, Object e, StackTrace? s) => Container(
      height: height,
      color: MCColors.background,
      alignment: Alignment.center,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(Icons.image_outlined, color: MCColors.muted, size: 28),
          const SizedBox(height: 8),
          Text(
            tr(context, 'फ़ोटो उपलब्ध नहीं', 'Photo unavailable'),
            style: const TextStyle(color: MCColors.muted, fontSize: 12),
          ),
        ],
      ),
    );
    if (source.startsWith('asset:')) {
      return Image.asset(
        source.substring(6),
        width: double.infinity,
        height: height,
        fit: fit,
        errorBuilder: fallback,
      );
    }
    if (source.startsWith('data:')) {
      try {
        return Image.memory(
          base64Decode(source.split(',').last),
          width: double.infinity,
          height: height,
          fit: fit,
          errorBuilder: fallback,
        );
      } catch (e) {
        return fallback(context, e, null);
      }
    }
    if (source.isEmpty) return fallback(context, 'missing', null);
    return Image.network(
      source,
      width: double.infinity,
      height: height,
      fit: fit,
      errorBuilder: fallback,
      loadingBuilder: (c, child, p) => p == null
          ? child
          : Container(
              height: height,
              color: MCColors.background,
              alignment: Alignment.center,
              child: const SizedBox(
                width: 24,
                height: 24,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            ),
    );
  }
}

class EmptyState extends StatelessWidget {
  const EmptyState({
    super.key,
    required this.title,
    required this.message,
    this.icon = Icons.waving_hand_outlined,
    this.action,
    this.actionLabel,
  });
  final String title;
  final String message;
  final IconData icon;
  final VoidCallback? action;
  final String? actionLabel;
  @override
  Widget build(BuildContext context) => Container(
    width: double.infinity,
    padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 40),
    decoration: BoxDecoration(
      color: Colors.white,
      borderRadius: BorderRadius.circular(20),
      border: Border.all(color: MCColors.border),
    ),
    child: Column(
      children: [
        Container(
          padding: const EdgeInsets.all(18),
          decoration: const BoxDecoration(
            color: MCColors.greenSoft,
            shape: BoxShape.circle,
          ),
          child: Icon(icon, size: 30, color: MCColors.green),
        ),
        const SizedBox(height: 18),
        Text(
          title,
          textAlign: TextAlign.center,
          style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w800),
        ),
        const SizedBox(height: 8),
        Text(
          message,
          textAlign: TextAlign.center,
          style: const TextStyle(
            color: MCColors.muted,
            height: 1.6,
            fontSize: 13,
          ),
        ),
        if (action != null) ...[
          const SizedBox(height: 20),
          OutlinedButton(onPressed: action, child: Text(actionLabel!)),
        ],
      ],
    ),
  );
}

class SectionHeading extends StatelessWidget {
  const SectionHeading(this.title, {super.key, this.subtitle, this.trailing});
  final String title;
  final String? subtitle;
  final Widget? trailing;
  @override
  Widget build(BuildContext context) => Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Expanded(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: const TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.w800,
                letterSpacing: -.5,
                height: 1.4,
              ),
            ),
            if (subtitle != null) ...[
              const SizedBox(height: 5),
              Text(
                subtitle!,
                style: const TextStyle(
                  fontSize: 12,
                  color: MCColors.muted,
                  height: 1.5,
                ),
              ),
            ],
          ],
        ),
      ),
      if (trailing != null) trailing!,
    ],
  );
}
