import 'dart:async';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../controllers/app_controller.dart';
import '../../models/community.dart';
import '../../models/location.dart';
import '../../theme/app_theme.dart';
import '../widgets/common.dart';
import '../widgets/post_card.dart';

class FeedScreen extends StatefulWidget {
  const FeedScreen({super.key, required this.onCreate, required this.onPost});
  final VoidCallback onCreate;
  final void Function(CommunityPost) onPost;
  @override
  State<FeedScreen> createState() => _FeedScreenState();
}

class _FeedScreenState extends State<FeedScreen> {
  final _scroll = ScrollController();
  final _search = TextEditingController();
  final _focus = FocusNode();
  Timer? _debounce;
  @override
  void initState() {
    super.initState();
    _scroll.addListener(() {
      if (_scroll.position.extentAfter < 320) {
        context.read<AppController>().loadMore();
      }
    });
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final c = context.watch<AppController>();
    if (!_focus.hasFocus && _search.text != c.search) _search.text = c.search;
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _scroll.dispose();
    _search.dispose();
    _focus.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    final narrow = MediaQuery.sizeOf(context).width < 760;
    final horizontal = narrow ? 18.0 : 30.0;
    return RefreshIndicator(
      onRefresh: c.refresh,
      color: MCColors.primary,
      child: ListView(
        controller: _scroll,
        key: const PageStorageKey('local-feed'),
        physics: const AlwaysScrollableScrollPhysics(),
        padding: EdgeInsets.fromLTRB(
          horizontal,
          narrow ? 18 : 24,
          horizontal,
          narrow ? 100 : 36,
        ),
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  c.text('आपके आसपास', 'THE NEIGHBOURHOOD EDIT'),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    fontSize: 10,
                    color: MCColors.primary,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 1.7,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              if (c.isDemo)
                LabelPill(
                  text: c.text('DEMO · नमूना डेटा', 'DEMO · SAMPLE DATA'),
                  color: MCColors.muted,
                  background: const Color(0xFFEDF0E9),
                  small: true,
                ),
            ],
          ),
          const SizedBox(height: 10),
          SectionHeading(
            c.text(
              'पड़ोस की बात, पड़ोस के साथ।',
              'Good neighbours.\nGreat neighbourhoods.',
            ),
            subtitle: c.text(
              'छोटी बातें, साझा कोशिशें और अपना समुदाय।',
              'Local voices. Shared ideas. A place to belong.',
            ),
          ),
          SizedBox(height: narrow ? 14 : 20),
          _NeighbourhoodBanner(onCreate: widget.onCreate),
          SizedBox(height: narrow ? 12 : 19),
          _QuickStats(c.stats),
          SizedBox(height: narrow ? 14 : 22),
          TextField(
            controller: _search,
            focusNode: _focus,
            maxLength: 100,
            textInputAction: TextInputAction.search,
            decoration: InputDecoration(
              hintText: c.text(
                'अपने इलाके में खोजें…',
                'Search your neighbourhood…',
              ),
              counterText: '',
              prefixIcon: const Icon(
                Icons.search_rounded,
                size: 20,
                color: MCColors.muted,
              ),
              suffixIcon: _search.text.isNotEmpty
                  ? IconButton(
                      icon: const Icon(Icons.close, size: 18),
                      tooltip: c.text('खोज हटाएँ', 'Clear search'),
                      onPressed: () {
                        _debounce?.cancel();
                        _search.clear();
                        c.setSearch('');
                      },
                    )
                  : null,
            ),
            style: const TextStyle(fontSize: 13),
            onChanged: (s) {
              setState(() {});
              _debounce?.cancel();
              _debounce = Timer(
                const Duration(milliseconds: 350),
                () => c.setSearch(s),
              );
            },
            onSubmitted: (s) {
              _debounce?.cancel();
              c.setSearch(s);
              _focus.unfocus();
            },
          ),
          SizedBox(height: narrow ? 10 : 15),
          _ScopePicker(),
          SizedBox(height: narrow ? 12 : 18),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: [
                _FilterChip(
                  text: c.text('सभी', 'All posts'),
                  icon: Icons.grid_view_rounded,
                  active: c.filter == null,
                  onTap: () => c.setFilter(null),
                ),
                for (final type in PostType.values)
                  _FilterChip(
                    text: switch (type) {
                      PostType.civicIssue => c.text('समस्याएँ', 'Issues'),
                      PostType.localReview => c.text('समीक्षाएँ', 'Reviews'),
                      PostType.event => c.text('कार्यक्रम', 'Events'),
                      PostType.general => c.text('चर्चा', 'Chats'),
                    },
                    icon: type.icon,
                    active: c.filter == type,
                    onTap: () => c.setFilter(type),
                  ),
              ],
            ),
          ),
          const SizedBox(height: 20),
          Row(
            children: [
              Text(
                c.text('मोहल्ले की हलचल', 'What’s happening'),
                style: const TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w800,
                ),
              ),
              const Spacer(),
              PopupMenuButton<FeedSort>(
                initialValue: c.sort,
                onSelected: c.setSort,
                tooltip: c.text('क्रम बदलें', 'Sort feed'),
                itemBuilder: (_) => [
                  PopupMenuItem(
                    value: FeedSort.latest,
                    child: Text(c.text('सबसे नई', 'Newest first')),
                  ),
                  PopupMenuItem(
                    value: FeedSort.supported,
                    child: Text(
                      c.text('सबसे ज़्यादा समर्थन', 'Most supported'),
                    ),
                  ),
                ],
                child: Padding(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  child: Row(
                    children: [
                      const Icon(
                        Icons.tune_rounded,
                        size: 14,
                        color: MCColors.muted,
                      ),
                      const SizedBox(width: 5),
                      Text(
                        c.sort == FeedSort.latest
                            ? c.text('नई पोस्ट', 'Newest')
                            : c.text('लोकप्रिय', 'Top supported'),
                        style: const TextStyle(
                          fontSize: 11,
                          color: MCColors.muted,
                        ),
                      ),
                      const Icon(
                        Icons.keyboard_arrow_down,
                        size: 16,
                        color: MCColors.muted,
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          if (c.loading && c.posts.isEmpty) ...[
            const _LoadingCard(),
            const SizedBox(height: 14),
            const _LoadingCard(),
          ] else if (c.error != null && c.posts.isEmpty)
            EmptyState(
              title: c.text('थोड़ा रुकिए…', 'Let’s try that again'),
              message: c.error!,
              icon: Icons.wifi_off_rounded,
              action: c.refresh,
              actionLabel: c.text('फिर कोशिश करें', 'Retry'),
            )
          else if (c.posts.isEmpty)
            EmptyState(
              title: c.text(
                'यहाँ बातचीत शुरू हो सकती है',
                'Every neighbourhood starts with a hello',
              ),
              message: c.search.isNotEmpty || c.filter != null
                  ? c.text(
                      'इस खोज या फ़िल्टर में कोई पोस्ट नहीं। फ़िल्टर बदलकर देखें।',
                      'No posts match this search or filter. Try another one.',
                    )
                  : c.text(
                      'अपने वार्ड की पहली बात आप रखें। या आसपास का इलाका देखें।',
                      'Share something with your ward, or explore a wider area.',
                    ),
              action: c.search.isNotEmpty || c.filter != null
                  ? () {
                      _search.clear();
                      c.search = '';
                      c.setFilter(null);
                    }
                  : widget.onCreate,
              actionLabel: c.search.isNotEmpty || c.filter != null
                  ? c.text('फ़िल्टर हटाएँ', 'Clear filters')
                  : c.text('पहली पोस्ट बनाएँ', 'Start a conversation'),
            )
          else ...[
            if (c.loading)
              const Padding(
                padding: EdgeInsets.only(bottom: 14),
                child: LinearProgressIndicator(minHeight: 2),
              ),
            for (final p in c.posts) ...[
              PostCard(post: p, onOpen: () => widget.onPost(p)),
              const SizedBox(height: 16),
            ],
            if (c.loadingMore)
              const Padding(
                padding: EdgeInsets.all(16),
                child: Center(child: CircularProgressIndicator(strokeWidth: 2)),
              )
            else if (c.hasMore)
              OutlinedButton(
                onPressed: c.loadMore,
                child: Text(c.text('और पोस्ट देखें', 'Load more posts')),
              )
            else
              Padding(
                padding: const EdgeInsets.only(top: 12, bottom: 10),
                child: Column(
                  children: [
                    const Icon(
                      Icons.check_circle_outline,
                      color: MCColors.green,
                      size: 22,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      c.text(
                        'आप अपने इलाके की सारी नई बातें देख चुके हैं।',
                        'You’re all caught up with your neighbourhood.',
                      ),
                      textAlign: TextAlign.center,
                      style: const TextStyle(
                        color: MCColors.muted,
                        fontSize: 11,
                      ),
                    ),
                    if (c.scope == FeedScope.ward)
                      TextButton(
                        onPressed: () => c.setScope(FeedScope.area),
                        child: Text(
                          c.text(
                            'आसपास की बातें भी देखें →',
                            'Explore the wider area →',
                          ),
                          style: const TextStyle(fontSize: 12),
                        ),
                      ),
                  ],
                ),
              ),
          ],
          if (c.error != null && c.posts.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(
                c.error!,
                style: const TextStyle(fontSize: 12, color: MCColors.primary),
              ),
            ),
        ],
      ),
    );
  }
}

class _NeighbourhoodBanner extends StatelessWidget {
  const _NeighbourhoodBanner({required this.onCreate});
  final VoidCallback onCreate;
  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    return Container(
      height: MediaQuery.sizeOf(context).width < 760 ? 130 : 152,
      clipBehavior: Clip.antiAlias,
      decoration: BoxDecoration(
        color: const Color(0xFFF1EEE0),
        borderRadius: BorderRadius.circular(18),
      ),
      child: Stack(
        children: [
          Positioned.fill(
            child: Image.asset(
              'assets/images/neighborhood.jpg',
              fit: BoxFit.cover,
              alignment: Alignment.centerRight,
            ),
          ),
          Positioned.fill(
            child: DecoratedBox(
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [
                    const Color(0xFFF4F0E5),
                    const Color(0xFFF4F0E5).withValues(alpha: .92),
                    const Color(0xFFF4F0E5).withValues(alpha: 0),
                  ],
                  stops: const [0, .38, .78],
                ),
              ),
            ),
          ),
          Positioned(
            left: 20,
            right: 20,
            top: 16,
            bottom: 14,
            child: FittedBox(
              fit: BoxFit.scaleDown,
              alignment: Alignment.centerLeft,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    c.text(
                      'हमारा मोहल्ला. हमारी पहल.',
                      'OUR STREETS. OUR STORIES.',
                    ),
                    style: const TextStyle(
                      fontSize: 8,
                      letterSpacing: .8,
                      fontWeight: FontWeight.w800,
                      color: MCColors.green,
                    ),
                  ),
                  const SizedBox(height: 7),
                  Text(
                    c.text(
                      'एक छोटा कदम,\nबेहतर मोहल्ला।',
                      'A little together\ngoes a long way.',
                    ),
                    style: const TextStyle(
                      fontSize: 21,
                      height: 1.4,
                      fontWeight: FontWeight.w800,
                      letterSpacing: -.4,
                    ),
                  ),
                  const SizedBox(height: 10),
                  InkWell(
                    onTap: onCreate,
                    child: Padding(
                      padding: const EdgeInsets.symmetric(vertical: 4),
                      child: Row(
                        children: [
                          Text(
                            c.text('बात शुरू करें', 'Start a conversation'),
                            style: const TextStyle(
                              fontSize: 10,
                              color: MCColors.primary,
                              fontWeight: FontWeight.w800,
                            ),
                          ),
                          const SizedBox(width: 7),
                          const Icon(
                            Icons.arrow_forward_rounded,
                            size: 14,
                            color: MCColors.primary,
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _QuickStats extends StatelessWidget {
  const _QuickStats(this.stats);
  final CommunityStats stats;
  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    final values = [
      (
        stats.neighbours,
        c.text('पड़ोसी', 'Neighbours'),
        Icons.people_outline,
        MCColors.green,
      ),
      (
        stats.openIssues,
        c.text('खुले मुद्दे', 'Open issues'),
        Icons.campaign_outlined,
        MCColors.primary,
      ),
      (
        stats.resolved,
        c.text('सुलझा मुद्दा', 'Resolved'),
        Icons.task_alt,
        MCColors.amber,
      ),
    ];
    return Row(
      children: [
        for (var i = 0; i < values.length; i++) ...[
          if (i > 0) const SizedBox(width: 10),
          Expanded(
            child: Container(
              padding: const EdgeInsets.symmetric(vertical: 13, horizontal: 9),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: MCColors.border),
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(values[i].$3, size: 17, color: values[i].$4),
                  const SizedBox(width: 7),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '${values[i].$1}',
                          style: const TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                        Text(
                          values[i].$2,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(
                            fontSize: 8,
                            color: MCColors.muted,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ],
    );
  }
}

class _ScopePicker extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Row(
        children: [
          const Icon(Icons.radar_rounded, size: 16, color: MCColors.muted),
          const SizedBox(width: 8),
          for (final s in FeedScope.values.where(
            (s) => s != FeedScope.block || c.selectedLocation!.isRural,
          ))
            Padding(
              padding: const EdgeInsets.only(right: 7),
              child: InkWell(
                onTap: () => c.setScope(s),
                borderRadius: BorderRadius.circular(8),
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 10,
                    vertical: 7,
                  ),
                  decoration: BoxDecoration(
                    color: c.scope == s ? MCColors.ink : MCColors.surface,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: c.scope == s ? MCColors.ink : MCColors.border,
                    ),
                  ),
                  child: Text(
                    switch (s) {
                      FeedScope.ward => c.text('मेरा वार्ड', 'My ward'),
                      FeedScope.area =>
                        c.selectedLocation!.isRural
                            ? c.text('पंचायत', 'Panchayat')
                            : c.text('नगर निकाय', 'Local body'),
                      FeedScope.block => c.text('प्रखंड', 'Block'),
                      FeedScope.district => c.text('पूरा ज़िला', 'District'),
                    },
                    style: TextStyle(
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                      color: c.scope == s ? Colors.white : MCColors.muted,
                    ),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _FilterChip extends StatelessWidget {
  const _FilterChip({
    required this.text,
    required this.icon,
    required this.active,
    required this.onTap,
  });
  final String text;
  final IconData icon;
  final bool active;
  final VoidCallback onTap;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(right: 8),
    child: InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(11),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 11),
        decoration: BoxDecoration(
          color: active ? MCColors.primarySoft : Colors.white,
          borderRadius: BorderRadius.circular(11),
          border: Border.all(
            color: active
                ? MCColors.primary.withValues(alpha: .2)
                : MCColors.border,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              size: 15,
              color: active ? MCColors.primary : MCColors.muted,
            ),
            const SizedBox(width: 7),
            Text(
              text,
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w700,
                color: active ? MCColors.primary : MCColors.muted,
              ),
            ),
          ],
        ),
      ),
    ),
  );
}

class _LoadingCard extends StatelessWidget {
  const _LoadingCard();
  @override
  Widget build(BuildContext context) => Container(
    height: 190,
    padding: const EdgeInsets.all(20),
    decoration: BoxDecoration(
      color: Colors.white,
      borderRadius: BorderRadius.circular(20),
      border: Border.all(color: MCColors.border),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          width: 160,
          height: 30,
          decoration: BoxDecoration(
            color: MCColors.background,
            borderRadius: BorderRadius.circular(10),
          ),
        ),
        const SizedBox(height: 20),
        Container(height: 15, color: MCColors.background),
        const SizedBox(height: 10),
        Container(width: 240, height: 15, color: MCColors.background),
        const Spacer(),
        const SizedBox(
          width: 22,
          height: 22,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
      ],
    ),
  );
}
