import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../controllers/app_controller.dart';
import '../models/community.dart';
import '../theme/app_theme.dart';
import 'screens/community_screen.dart';
import 'screens/create_post_screen.dart';
import 'screens/feed_screen.dart';
import 'screens/map_screen.dart';
import 'screens/post_detail_screen.dart';
import 'screens/profile_screen.dart';
import 'widgets/common.dart';
import 'widgets/location_picker.dart';

class AppShell extends StatelessWidget {
  const AppShell({super.key});
  Future<void> _create(
    BuildContext context, [
    PostType type = PostType.general,
  ]) async {
    final post = await Navigator.push<CommunityPost>(
      context,
      MaterialPageRoute(builder: (_) => CreatePostScreen(initialType: type)),
    );
    if (post != null && context.mounted) {
      notifyUser(
        context,
        tr(
          context,
          'आपकी बात मोहल्ले में साझा हुई!',
          'Your post is part of the neighbourhood!',
        ),
      );
      _openPost(context, post);
    }
  }

  void _openPost(BuildContext context, CommunityPost post) =>
      Navigator.push<void>(
        context,
        MaterialPageRoute(builder: (_) => PostDetailScreen(post: post)),
      );

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    return LayoutBuilder(
      builder: (context, size) {
        final desktop = size.maxWidth >= 760;
        final wide = size.maxWidth >= 1240;
        final body = switch (c.tab) {
          0 => FeedScreen(
            onCreate: () => _create(context),
            onPost: (p) => _openPost(context, p),
          ),
          1 => NeighbourhoodMapScreen(onPost: (p) => _openPost(context, p)),
          2 => CommunityScreen(
            onCreateEvent: () => _create(context, PostType.event),
            onPost: (p) => _openPost(context, p),
          ),
          _ => ProfileScreen(onPost: (p) => _openPost(context, p)),
        };
        return Scaffold(
          body: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 1320),
              child: SafeArea(
                bottom: false,
                child: Row(
                  children: [
                    if (desktop) _Sidebar(onCreate: () => _create(context)),
                    Expanded(
                      child: Column(
                        children: [
                          _TopBar(desktop: desktop),
                          Expanded(
                            child: Row(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [
                                Expanded(child: body),
                                if (wide) const _CommunitySidePanel(),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
          bottomNavigationBar: desktop
              ? null
              : NavigationBar(
                  selectedIndex: c.tab,
                  onDestinationSelected: c.setTab,
                  destinations: [
                    NavigationDestination(
                      icon: const Icon(Icons.home_outlined),
                      selectedIcon: const Icon(Icons.home_rounded),
                      label: c.text('मोहल्ला', 'Feed'),
                    ),
                    NavigationDestination(
                      icon: const Icon(Icons.map_outlined),
                      selectedIcon: const Icon(Icons.map_rounded),
                      label: c.text('नक्शा', 'Map'),
                    ),
                    NavigationDestination(
                      icon: const Icon(Icons.people_outline),
                      selectedIcon: const Icon(Icons.people_rounded),
                      label: c.text('समुदाय', 'Together'),
                    ),
                    NavigationDestination(
                      icon: const Icon(Icons.person_outline),
                      selectedIcon: const Icon(Icons.person_rounded),
                      label: c.text('मैं', 'You'),
                    ),
                  ],
                ),
          floatingActionButton: desktop
              ? null
              : FloatingActionButton.extended(
                  onPressed: () => _create(context),
                  icon: const Icon(Icons.add, size: 22),
                  label: Text(
                    c.text('पोस्ट', 'Post'),
                    style: const TextStyle(fontWeight: FontWeight.w800),
                  ),
                ),
        );
      },
    );
  }
}

class _Sidebar extends StatelessWidget {
  const _Sidebar({required this.onCreate});
  final VoidCallback onCreate;
  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    return Container(
      width: 228,
      padding: const EdgeInsets.fromLTRB(24, 30, 20, 24),
      decoration: const BoxDecoration(
        color: Colors.white,
        border: Border(right: BorderSide(color: MCColors.border)),
      ),
      child: _SidebarScroll(
        children: [
          const Row(
            children: [
              BrandMark(size: 41),
              SizedBox(width: 11),
              Expanded(
                child: Text(
                  'Mohalla\nCharcha',
                  style: TextStyle(
                    fontSize: 21,
                    fontWeight: FontWeight.w800,
                    height: 1.08,
                    letterSpacing: -.7,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 13),
          Padding(
            padding: const EdgeInsets.only(left: 2),
            child: Text(
              c.text('बिहार · अपने लोगों की जगह', 'BIHAR · A PLACE TO BELONG'),
              style: const TextStyle(
                color: MCColors.muted,
                fontSize: 8,
                letterSpacing: 1.1,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
          const SizedBox(height: 40),
          for (final item in [
            (0, Icons.home_outlined, 'मेरा मोहल्ला', 'My neighbourhood'),
            (1, Icons.map_outlined, 'आसपास का नक्शा', 'Around me'),
            (2, Icons.people_outline, 'साथ मिलकर', 'Better together'),
            (3, Icons.person_outline, 'मेरी जगह', 'My little corner'),
          ])
            Padding(
              padding: const EdgeInsets.only(bottom: 9),
              child: Material(
                color: c.tab == item.$1
                    ? MCColors.primarySoft
                    : Colors.transparent,
                borderRadius: BorderRadius.circular(12),
                child: InkWell(
                  onTap: () => c.setTab(item.$1),
                  borderRadius: BorderRadius.circular(12),
                  child: Padding(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 12,
                      vertical: 14,
                    ),
                    child: Row(
                      children: [
                        Icon(
                          item.$2,
                          size: 20,
                          color: c.tab == item.$1
                              ? MCColors.primary
                              : MCColors.muted,
                        ),
                        const SizedBox(width: 11),
                        Expanded(
                          child: Text(
                            c.text(item.$3, item.$4),
                            style: TextStyle(
                              fontSize: 11,
                              fontWeight: c.tab == item.$1
                                  ? FontWeight.w800
                                  : FontWeight.w600,
                              color: c.tab == item.$1
                                  ? MCColors.primary
                                  : MCColors.ink,
                            ),
                          ),
                        ),
                        if (c.tab == item.$1)
                          Container(
                            width: 5,
                            height: 5,
                            decoration: const BoxDecoration(
                              color: MCColors.primary,
                              shape: BoxShape.circle,
                            ),
                          ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          const SizedBox(height: 22),
          SizedBox(
            width: double.infinity,
            child: FilledButton.icon(
              onPressed: onCreate,
              icon: const Icon(Icons.add, size: 20),
              label: Text(
                c.text('अपनी बात रखें', 'Share something'),
                style: const TextStyle(fontSize: 11),
              ),
            ),
          ),
          const Spacer(),
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: MCColors.greenSoft,
              borderRadius: BorderRadius.circular(14),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Icon(Icons.spa_outlined, color: MCColors.green, size: 24),
                const SizedBox(height: 10),
                Text(
                  c.text(
                    'अच्छे पड़ोसी,\nअच्छा मोहल्ला।',
                    'A better place,\none neighbour at a time.',
                  ),
                  style: const TextStyle(
                    color: MCColors.green,
                    fontSize: 13,
                    height: 1.7,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  c.text(
                    'P2P समुदाय.\nकोई सरकारी टिकट नहीं।',
                    'People-to-people.\nNo official ticket routing.',
                  ),
                  style: const TextStyle(
                    fontSize: 9,
                    height: 1.8,
                    color: MCColors.green,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 22),
          InkWell(
            onTap: () => c.setTab(3),
            child: Row(
              children: [
                ProfileAvatar(c.profile!, size: 34),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        c.profile!.name,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          fontSize: 10,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                      Text(
                        c.text('अपनी प्रोफ़ाइल देखें', 'Your profile'),
                        style: const TextStyle(
                          color: MCColors.muted,
                          fontSize: 9,
                        ),
                      ),
                    ],
                  ),
                ),
                const Icon(
                  Icons.chevron_right,
                  size: 17,
                  color: MCColors.muted,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _TopBar extends StatelessWidget {
  const _TopBar({required this.desktop});
  final bool desktop;
  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    final area = c.selectedLocation!;
    return Container(
      height: desktop ? 82 : 76,
      padding: EdgeInsets.symmetric(horizontal: desktop ? 30 : 18),
      decoration: const BoxDecoration(
        color: Colors.white,
        border: Border(bottom: BorderSide(color: MCColors.border)),
      ),
      child: Row(
        children: [
          if (!desktop) ...[
            const BrandMark(size: 35),
            const SizedBox(width: 11),
          ],
          Expanded(
            child: InkWell(
              onTap: () async {
                final a = await pickArea(context);
                if (a != null) await c.selectLocation(a);
              },
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (desktop) ...[
                    Container(
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: MCColors.primarySoft,
                        borderRadius: BorderRadius.circular(11),
                      ),
                      child: const Icon(
                        Icons.location_on_outlined,
                        color: MCColors.primary,
                        size: 20,
                      ),
                    ),
                    const SizedBox(width: 12),
                  ],
                  Flexible(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '${area.shortLabel} · Ward ${area.ward}',
                          style: TextStyle(
                            fontSize: desktop ? 15 : 12,
                            fontWeight: FontWeight.w800,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 5),
                        Text(
                          '${area.isRural ? '${area.panchayat} · ${area.blockOrUlb} · ' : ''}${area.district}, Bihar',
                          style: TextStyle(
                            fontSize: desktop ? 10 : 9,
                            color: MCColors.muted,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 8),
                  const Icon(
                    Icons.keyboard_arrow_down_rounded,
                    size: 18,
                    color: MCColors.muted,
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(width: 8),
          TextButton(
            onPressed: () => safeAction(context, c.toggleLanguage),
            style: TextButton.styleFrom(
              foregroundColor: MCColors.muted,
              minimumSize: const Size(36, 36),
              padding: const EdgeInsets.all(5),
            ),
            child: Text(
              c.isHindi ? 'EN' : 'हिन्दी',
              style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w800),
            ),
          ),
          if (desktop) ...[
            const SizedBox(width: 18),
            Container(width: 1, height: 28, color: MCColors.border),
            const SizedBox(width: 20),
          ],
          InkWell(
            onTap: () => c.setTab(3),
            borderRadius: BorderRadius.circular(30),
            child: ProfileAvatar(c.profile!, size: desktop ? 40 : 34),
          ),
        ],
      ),
    );
  }
}

class _CommunitySidePanel extends StatelessWidget {
  const _CommunitySidePanel();
  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    final a = c.selectedLocation!;
    return Container(
      width: 288,
      decoration: const BoxDecoration(
        border: Border(left: BorderSide(color: MCColors.border)),
      ),
      child: ListView(
        padding: const EdgeInsets.fromLTRB(22, 28, 24, 24),
        children: [
          Container(
            padding: const EdgeInsets.all(20),
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
                      Icons.cottage_outlined,
                      size: 22,
                      color: MCColors.green,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      c.text('अपना मोहल्ला', 'Your neighbourhood'),
                      style: const TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 18),
                Text(
                  a.shortLabel,
                  style: const TextStyle(
                    fontSize: 22,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  'Ward ${a.ward} · ${a.district}',
                  style: const TextStyle(fontSize: 11, color: MCColors.muted),
                ),
                const SizedBox(height: 11),
                Text(
                  a.isRural
                      ? '${a.blockOrUlb}\nGram Panchayat: ${a.panchayat}'
                      : a.blockOrUlb,
                  style: const TextStyle(
                    fontSize: 10,
                    height: 1.7,
                    color: MCColors.muted,
                  ),
                ),
                const SizedBox(height: 18),
                const Divider(),
                const SizedBox(height: 15),
                for (final item in [
                  (
                    c.stats.neighbours,
                    c.text('जुड़े हुए पड़ोसी', 'Local neighbours'),
                    MCColors.green,
                  ),
                  (
                    c.stats.openIssues,
                    c.text('चर्चा में मुद्दे', 'Open conversations'),
                    MCColors.primary,
                  ),
                  (
                    c.stats.resolved,
                    c.text('पड़ोसियों ने सुलझाए', 'Resolved together'),
                    MCColors.amber,
                  ),
                ])
                  Padding(
                    padding: const EdgeInsets.only(bottom: 12),
                    child: Row(
                      children: [
                        Container(
                          width: 6,
                          height: 6,
                          decoration: BoxDecoration(
                            color: item.$3,
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            item.$2,
                            style: const TextStyle(
                              fontSize: 10,
                              color: MCColors.muted,
                            ),
                          ),
                        ),
                        Text(
                          '${item.$1}',
                          style: const TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                      ],
                    ),
                  ),
                if (c.isDemo)
                  Text(
                    c.text(
                      'सभी आँकड़े नमूना डेटा हैं।',
                      'All figures are sample data.',
                    ),
                    style: const TextStyle(fontSize: 8, color: MCColors.muted),
                  ),
                const SizedBox(height: 10),
                SizedBox(
                  width: double.infinity,
                  child: OutlinedButton(
                    onPressed: () => c.setTab(2),
                    child: Text(
                      c.text('समुदाय को जानें', 'Meet the community'),
                      style: const TextStyle(fontSize: 11),
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 22),
          Text(
            c.text('एक अच्छा पड़ोसी…', 'A good neighbour…'),
            style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 14),
          for (final item in [
            (
              Icons.favorite_border,
              'सम्मान से बात करता है',
              'Speaks with kindness',
            ),
            (
              Icons.fact_check_outlined,
              'सही जानकारी साझा करता है',
              'Checks before sharing',
            ),
            (
              Icons.shield_outlined,
              'निजी बातें सुरक्षित रखता है',
              'Keeps private things private',
            ),
          ])
            Padding(
              padding: const EdgeInsets.only(bottom: 13),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(item.$1, size: 16, color: MCColors.green),
                  const SizedBox(width: 9),
                  Expanded(
                    child: Text(
                      c.text(item.$2, item.$3),
                      style: const TextStyle(
                        fontSize: 10,
                        height: 1.5,
                        color: MCColors.muted,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          const SizedBox(height: 12),
          const Divider(),
          const SizedBox(height: 20),
          Text(
            c.text(
              'अपने लोगों की जगह।\nबिहार के लिए, प्यार से।',
              'A place for your people.\nMade for Bihar, with care.',
            ),
            style: const TextStyle(
              fontSize: 10,
              height: 1.9,
              color: MCColors.muted,
            ),
          ),
          const SizedBox(height: 12),
          const Text(
            'MOHALLA CHARCHA © 2026',
            style: TextStyle(
              fontSize: 8,
              letterSpacing: .8,
              color: MCColors.muted,
            ),
          ),
        ],
      ),
    );
  }
}

class _SidebarScroll extends StatelessWidget {
  const _SidebarScroll({required this.children});
  final List<Widget> children;
  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, box) => SingleChildScrollView(
      child: ConstrainedBox(
        constraints: BoxConstraints(minHeight: box.maxHeight),
        child: IntrinsicHeight(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: children,
          ),
        ),
      ),
    ),
  );
}
