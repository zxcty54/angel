import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../controllers/app_controller.dart';
import '../../theme/app_theme.dart';
import '../widgets/common.dart';
import '../widgets/location_picker.dart';

/// First-install education comes BEFORE demo/feed or live OTP/profile setup.
/// Replay from Profile does not reset preferences, session or community data.
class WelcomeScreen extends StatefulWidget {
  const WelcomeScreen({super.key, this.replay = false});
  final bool replay;

  @override
  State<WelcomeScreen> createState() => _WelcomeScreenState();
}

class _WelcomeScreenState extends State<WelcomeScreen> {
  final _pages = PageController();
  int _page = 0;
  bool _busy = false;

  @override
  void dispose() {
    _pages.dispose();
    super.dispose();
  }

  Future<void> _go(int page) async {
    if (_busy) return;
    if (MediaQuery.disableAnimationsOf(context)) {
      _pages.jumpToPage(page);
    } else {
      await _pages.animateToPage(
        page,
        duration: const Duration(milliseconds: 260),
        curve: Curves.easeInOut,
      );
    }
  }

  Future<void> _finish() async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      if (widget.replay) {
        if (mounted) Navigator.of(context).pop();
      } else {
        await context.read<AppController>().completeWelcome();
      }
    } catch (e) {
      if (mounted) notifyUser(context, AppController.friendlyError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _chooseWard() async {
    if (_busy) return;
    final c = context.read<AppController>();
    if (!c.isDemo || c.profile == null) return;
    setState(() => _busy = true);
    try {
      final home = await pickArea(context, initial: c.profile!.location);
      if (!mounted || home == null) return;
      await c.saveProfile(c.profile!.name, home, '');
    } catch (e) {
      if (mounted) notifyUser(context, AppController.friendlyError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    return PopScope(
      canPop: _page == 0 && !_busy,
      onPopInvokedWithResult: (didPop, result) {
        if (!didPop && _page > 0 && !_busy) _go(_page - 1);
      },
      child: Scaffold(
        body: SafeArea(
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 1120),
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                child: Column(
                  children: [
                    Padding(
                      padding: const EdgeInsets.symmetric(vertical: 16),
                      child: Row(
                        children: [
                          const BrandMark(size: 42),
                          const SizedBox(width: 11),
                          const Expanded(
                            child: Text(
                              'Mohalla\nCharcha',
                              style: TextStyle(
                                fontSize: 17,
                                fontWeight: FontWeight.w800,
                                height: 1.15,
                              ),
                            ),
                          ),
                          Flexible(
                            child: Wrap(
                              alignment: WrapAlignment.end,
                              children: [
                                TextButton(
                                  key: const Key('welcome_language'),
                                  onPressed: _busy
                                      ? null
                                      : () => safeAction(
                                          context,
                                          c.toggleLanguage,
                                        ),
                                  style: TextButton.styleFrom(
                                    minimumSize: const Size(40, 40),
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 8,
                                    ),
                                  ),
                                  child: Text(c.isHindi ? 'EN' : 'हिन्दी'),
                                ),
                                TextButton(
                                  key: const Key('welcome_skip'),
                                  onPressed: _busy ? null : _finish,
                                  style: TextButton.styleFrom(
                                    foregroundColor: MCColors.muted,
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 8,
                                    ),
                                  ),
                                  child: Text(
                                    widget.replay
                                        ? c.text('बंद करें', 'Close')
                                        : c.text('छोड़ें', 'Skip'),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                    Expanded(
                      child: LayoutBuilder(
                        builder: (context, constraints) {
                          final wide = constraints.maxWidth >= 850;
                          final artHeight = wide
                              ? 420.0
                              : (constraints.maxHeight *
                                        (_page == 2 ? .35 : .45))
                                    .clamp(165.0, 270.0)
                                    .toDouble();
                          return PageView.builder(
                            key: const Key('welcome_pages'),
                            controller: _pages,
                            itemCount: 3,
                            onPageChanged: (index) =>
                                setState(() => _page = index),
                            itemBuilder: (context, index) {
                              final art = _WelcomeArt(
                                index: index,
                                height: artHeight,
                              );
                              final content = _WelcomeContent(
                                index: index,
                                wide: wide,
                                busy: _busy,
                                onChooseWard: _chooseWard,
                              );
                              return SingleChildScrollView(
                                key: Key('welcome_scroll_$index'),
                                padding: const EdgeInsets.symmetric(
                                  vertical: 10,
                                ),
                                child: wide
                                    ? Row(
                                        crossAxisAlignment:
                                            CrossAxisAlignment.center,
                                        children: [
                                          Expanded(flex: 6, child: art),
                                          const SizedBox(width: 54),
                                          Expanded(flex: 5, child: content),
                                        ],
                                      )
                                    : Column(
                                        crossAxisAlignment:
                                            CrossAxisAlignment.start,
                                        children: [
                                          art,
                                          const SizedBox(height: 23),
                                          content,
                                        ],
                                      ),
                              );
                            },
                          );
                        },
                      ),
                    ),
                    Padding(
                      padding: const EdgeInsets.only(top: 14, bottom: 16),
                      child: Center(
                        child: ConstrainedBox(
                          constraints: const BoxConstraints(maxWidth: 460),
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Semantics(
                                label: c.text(
                                  'चरण ${_page + 1}, कुल 3',
                                  'Step ${_page + 1} of 3',
                                ),
                                excludeSemantics: true,
                                child: Row(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    for (var i = 0; i < 3; i++)
                                      AnimatedContainer(
                                        duration: const Duration(
                                          milliseconds: 180,
                                        ),
                                        margin: const EdgeInsets.symmetric(
                                          horizontal: 3,
                                        ),
                                        height: 7,
                                        width: _page == i ? 25 : 7,
                                        decoration: BoxDecoration(
                                          color: _page == i
                                              ? MCColors.primary
                                              : MCColors.border,
                                          borderRadius: BorderRadius.circular(
                                            10,
                                          ),
                                        ),
                                      ),
                                    const SizedBox(width: 11),
                                    Text(
                                      '${_page + 1} / 3',
                                      style: const TextStyle(
                                        fontSize: 11,
                                        color: MCColors.muted,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                              const SizedBox(height: 17),
                              Row(
                                children: [
                                  if (_page > 0) ...[
                                    IconButton.outlined(
                                      key: const Key('welcome_back'),
                                      tooltip: c.text(
                                        'पिछला चरण',
                                        'Previous step',
                                      ),
                                      onPressed: _busy
                                          ? null
                                          : () => _go(_page - 1),
                                      icon: const Icon(
                                        Icons.arrow_back_rounded,
                                        size: 20,
                                      ),
                                    ),
                                    const SizedBox(width: 12),
                                  ],
                                  Expanded(
                                    child: FilledButton(
                                      key: Key(
                                        _page == 2
                                            ? 'welcome_finish'
                                            : 'welcome_next',
                                      ),
                                      onPressed: _busy
                                          ? null
                                          : _page == 2
                                          ? _finish
                                          : () => _go(_page + 1),
                                      child: Row(
                                        mainAxisAlignment:
                                            MainAxisAlignment.center,
                                        children: [
                                          Flexible(
                                            child: Text(
                                              _busy
                                                  ? c.text(
                                                      'थोड़ा रुकें…',
                                                      'One moment…',
                                                    )
                                                  : _page < 2
                                                  ? c.text('आगे बढ़ें', 'Next')
                                                  : widget.replay
                                                  ? c.text('समझ गए!', 'Got it!')
                                                  : c.isDemo
                                                  ? c.text(
                                                      'अपना मोहल्ला खोलें',
                                                      'Explore my mohalla',
                                                    )
                                                  : c.text(
                                                      'मोबाइल से जुड़ें',
                                                      'Join with my phone',
                                                    ),
                                              textAlign: TextAlign.center,
                                            ),
                                          ),
                                          const SizedBox(width: 10),
                                          const Icon(
                                            Icons.arrow_forward_rounded,
                                            size: 19,
                                          ),
                                        ],
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 12),
                              Text(
                                c.isDemo
                                    ? c.text(
                                        'डेमो · कोई SMS नहीं भेजा जाएगा',
                                        'DEMO · no SMS will be sent',
                                      )
                                    : c.text(
                                        'अपनों की जगह · P2P समुदाय',
                                        'A place for neighbours · P2P community',
                                      ),
                                textAlign: TextAlign.center,
                                style: const TextStyle(
                                  color: MCColors.muted,
                                  fontSize: 10,
                                  height: 1.5,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _WelcomeContent extends StatelessWidget {
  const _WelcomeContent({
    required this.index,
    required this.wide,
    required this.busy,
    required this.onChooseWard,
  });
  final int index;
  final bool wide;
  final bool busy;
  final VoidCallback onChooseWard;

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    final kicker = switch (index) {
      0 => c.text('नमस्ते, बिहार!', 'HELLO, BIHAR!'),
      1 => c.text('सबसे पहले, आपका इलाका', 'LOCAL FIRST. ALWAYS.'),
      _ => c.text('छोटे कदम, साथ मिलकर', 'GOOD NEIGHBOURS. GREAT COMMUNITY.'),
    };
    final title = switch (index) {
      0 => c.text('अपना मोहल्ला,\nअपनी आवाज़।', 'Your mohalla.\nYour voice.'),
      1 => c.text('बात शुरू हो\nअपने वार्ड से।', 'Start with\nyour home ward.'),
      _ => c.text(
        'साथ मिलकर,\nबेहतर मोहल्ला।',
        'Small acts.\nReal togetherness.',
      ),
    };
    final description = switch (index) {
      0 => c.text(
        'आस-पास की बातें, अच्छे ठिकाने और साथ आने के मौके। बिहार के पड़ोसियों की अपनी जगह।',
        'Everyday conversations, honest local reviews and reasons to get together. A little corner of Bihar that feels like home.',
      ),
      1 => c.text(
        'पहले अपना वार्ड देखें। फिर चाहें तो नगर निकाय, ग्राम पंचायत, प्रखंड या पूरे जिले तक बात बढ़ाएँ।',
        'See your own ward first. Then widen the conversation to your ULB, gram panchayat, block or district.',
      ),
      _ => c.text(
        'मुद्दा साझा करें, साथ दें और मिलकर कदम उठाएँ। समाधान पड़ोसियों के साथ शुरू होता है।',
        'Share a concern, lend your support and take a small step together. Community action starts with us.',
      ),
    };
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          kicker,
          style: const TextStyle(
            fontSize: 10,
            fontWeight: FontWeight.w800,
            color: MCColors.primary,
            letterSpacing: 1.2,
          ),
        ),
        const SizedBox(height: 10),
        Semantics(
          header: true,
          child: Text(
            title,
            key: Key('welcome_title_$index'),
            style: TextStyle(
              fontSize: wide ? 40 : 30,
              height: 1.35,
              fontWeight: FontWeight.w800,
              letterSpacing: -.8,
            ),
          ),
        ),
        const SizedBox(height: 12),
        Text(
          description,
          style: const TextStyle(
            fontSize: 13,
            height: 1.85,
            color: MCColors.muted,
          ),
        ),
        if (index == 0) ...[
          const SizedBox(height: 18),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _MiniLabel(Icons.home_outlined, c.text('पड़ोस', 'Neighbours')),
              _MiniLabel(
                Icons.forum_outlined,
                c.text('चर्चा', 'Conversations'),
              ),
              _MiniLabel(Icons.diversity_1_outlined, c.text('साथ', 'Together')),
            ],
          ),
        ],
        if (index == 1) ...[
          const SizedBox(height: 18),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: MCColors.border),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  c.text('शहर', 'URBAN'),
                  style: const TextStyle(
                    fontSize: 10,
                    color: MCColors.green,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                const SizedBox(height: 5),
                Text(
                  c.text('जिला → नगर निकाय → वार्ड', 'District → ULB → Ward'),
                  style: const TextStyle(fontSize: 12, height: 1.6),
                ),
                const SizedBox(height: 12),
                Text(
                  c.text('गाँव', 'RURAL'),
                  style: const TextStyle(
                    fontSize: 10,
                    color: MCColors.green,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                const SizedBox(height: 5),
                Text(
                  c.text(
                    'जिला → प्रखंड → ग्राम पंचायत → वार्ड',
                    'District → Block → Gram Panchayat → Ward',
                  ),
                  style: const TextStyle(fontSize: 12, height: 1.6),
                ),
              ],
            ),
          ),
          const SizedBox(height: 13),
          if (c.isDemo && c.profile != null)
            SizedBox(
              width: double.infinity,
              child: OutlinedButton.icon(
                key: const Key('welcome_choose_ward'),
                onPressed: busy ? null : onChooseWard,
                icon: const Icon(Icons.location_on_outlined, size: 18),
                label: Text(
                  '${c.text('डेमो वार्ड', 'Demo ward')}: ${c.profile!.location.shortLabel} · ${c.profile!.location.ward}',
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            )
          else if (!c.isDemo)
            Text(
              c.text(
                'फोन सत्यापन के बाद आप अपना असली वार्ड चुनेंगे।',
                'Choose your real home ward after phone verification.',
              ),
              style: const TextStyle(
                fontSize: 11,
                color: MCColors.green,
                height: 1.7,
              ),
            ),
        ],
        if (index == 2) ...[
          const SizedBox(height: 19),
          _Guideline(
            Icons.shield_outlined,
            c.text('नंबर निजी है', 'Your number stays private'),
            c.text(
              'पड़ोसियों को आपका मोबाइल नंबर नहीं दिखता।',
              'Other neighbours do not see your phone number.',
            ),
          ),
          const SizedBox(height: 12),
          _Guideline(
            Icons.location_off_outlined,
            c.text('GPS की ज़रूरत नहीं', 'No GPS required'),
            c.text(
              'आप इलाका चुनते हैं। सटीक घर का पता साझा न करें।',
              'You choose the area. Do not post your exact home address.',
            ),
          ),
          const SizedBox(height: 12),
          _Guideline(
            Icons.volunteer_activism_outlined,
            c.text('पड़ोसियों का नेटवर्क', 'People, not departments'),
            c.text(
              'कोई सरकारी टिकट या विभागों तक रूटिंग नहीं।',
              'No government tickets or routing to officials.',
            ),
          ),
        ],
      ],
    );
  }
}

class _MiniLabel extends StatelessWidget {
  const _MiniLabel(this.icon, this.label);
  final IconData icon;
  final String label;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
    decoration: BoxDecoration(
      color: MCColors.greenSoft,
      borderRadius: BorderRadius.circular(8),
    ),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 14, color: MCColors.green),
        const SizedBox(width: 6),
        Text(
          label,
          style: const TextStyle(
            fontSize: 10,
            color: MCColors.green,
            fontWeight: FontWeight.w700,
          ),
        ),
      ],
    ),
  );
}

class _Guideline extends StatelessWidget {
  const _Guideline(this.icon, this.title, this.description);
  final IconData icon;
  final String title, description;
  @override
  Widget build(BuildContext context) => Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Container(
        padding: const EdgeInsets.all(9),
        decoration: BoxDecoration(
          color: MCColors.greenSoft,
          borderRadius: BorderRadius.circular(11),
        ),
        child: Icon(icon, color: MCColors.green, size: 19),
      ),
      const SizedBox(width: 12),
      Expanded(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w800),
            ),
            const SizedBox(height: 2),
            Text(
              description,
              style: const TextStyle(
                fontSize: 10,
                height: 1.7,
                color: MCColors.muted,
              ),
            ),
          ],
        ),
      ),
    ],
  );
}

class _WelcomeArt extends StatelessWidget {
  const _WelcomeArt({required this.index, required this.height});
  final int index;
  final double height;

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    return ClipRRect(
      borderRadius: BorderRadius.circular(24),
      child: SizedBox(
        width: double.infinity,
        height: height,
        child: switch (index) {
          0 => Stack(
            fit: StackFit.expand,
            children: [
              Image.asset(
                'assets/images/neighborhood.jpg',
                fit: BoxFit.cover,
                alignment: const Alignment(.45, 0),
                excludeFromSemantics: true,
              ),
              Positioned(
                left: 14,
                top: 14,
                child: _ArtBadge(
                  Icons.waving_hand_outlined,
                  c.text('यहाँ अपनापन है।', 'You belong here.'),
                ),
              ),
            ],
          ),
          1 => Stack(
            fit: StackFit.expand,
            children: [
              const CustomPaint(painter: _WardArtPainter()),
              Align(
                alignment: const Alignment(-.48, -.42),
                child: _MapDot(Icons.home_rounded, MCColors.primary),
              ),
              Align(
                alignment: const Alignment(.38, .08),
                child: _MapDot(Icons.storefront_rounded, MCColors.amber),
              ),
              Align(
                alignment: const Alignment(-.1, .46),
                child: _MapDot(Icons.people_alt_rounded, MCColors.green),
              ),
              Positioned(
                left: 14,
                top: 14,
                child: _ArtBadge(
                  Icons.near_me_outlined,
                  c.text('अपना वार्ड · हमेशा पहले', 'Your ward · always first'),
                ),
              ),
              Positioned(
                right: 14,
                bottom: 14,
                child: Text(
                  c.text('चित्रात्मक नक्शा', 'Illustrative map'),
                  style: const TextStyle(fontSize: 9, color: MCColors.muted),
                ),
              ),
            ],
          ),
          _ => Container(
            color: MCColors.greenSoft,
            child: Stack(
              fit: StackFit.expand,
              children: [
                const Align(
                  alignment: Alignment.center,
                  child: BrandMark(size: 86),
                ),
                Positioned(
                  top: 17,
                  left: 15,
                  child: _ArtBadge(
                    Icons.forum_outlined,
                    c.text('हम साथ हैं।', 'We are in this together.'),
                  ),
                ),
                const Align(
                  alignment: Alignment(-.65, .50),
                  child: _Neighbour(
                    Icons.person_rounded,
                    MCColors.primarySoft,
                    MCColors.primary,
                  ),
                ),
                const Align(
                  alignment: Alignment(.61, .45),
                  child: _Neighbour(
                    Icons.person_rounded,
                    MCColors.amberSoft,
                    MCColors.amber,
                  ),
                ),
                const Align(
                  alignment: Alignment(.54, -.42),
                  child: _Neighbour(
                    Icons.person_rounded,
                    Colors.white,
                    MCColors.green,
                  ),
                ),
              ],
            ),
          ),
        },
      ),
    );
  }
}

class _ArtBadge extends StatelessWidget {
  const _ArtBadge(this.icon, this.label);
  final IconData icon;
  final String label;
  @override
  Widget build(BuildContext context) => Container(
    constraints: const BoxConstraints(maxWidth: 245),
    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
    decoration: BoxDecoration(
      color: const Color(0xF8FFFFFF),
      borderRadius: BorderRadius.circular(10),
    ),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 14, color: MCColors.green),
        const SizedBox(width: 7),
        Flexible(
          child: Text(
            label,
            style: const TextStyle(
              fontSize: 10,
              fontWeight: FontWeight.w700,
              color: MCColors.ink,
            ),
          ),
        ),
      ],
    ),
  );
}

class _MapDot extends StatelessWidget {
  const _MapDot(this.icon, this.color);
  final IconData icon;
  final Color color;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(11),
    decoration: BoxDecoration(
      color: color,
      shape: BoxShape.circle,
      border: Border.all(color: Colors.white, width: 4),
      boxShadow: const [
        BoxShadow(
          color: Color(0x15000000),
          blurRadius: 12,
          offset: Offset(0, 4),
        ),
      ],
    ),
    child: Icon(icon, size: 20, color: Colors.white),
  );
}

class _Neighbour extends StatelessWidget {
  const _Neighbour(this.icon, this.background, this.ink);
  final IconData icon;
  final Color background, ink;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(10),
    decoration: BoxDecoration(
      color: background,
      shape: BoxShape.circle,
      border: Border.all(color: Colors.white, width: 3),
    ),
    child: Icon(icon, color: ink, size: 27),
  );
}

class _WardArtPainter extends CustomPainter {
  const _WardArtPainter();
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()..color = const Color(0xFFE9EEDC);
    canvas.drawRect(Offset.zero & size, paint);
    final cellWidth = size.width / 5;
    final cellHeight = size.height / 3;
    for (var row = 0; row < 3; row++) {
      for (var col = 0; col < 5; col++) {
        paint.color = (row + col).isEven
            ? const Color(0xFFD8E2C9)
            : const Color(0xFFE5D9C5);
        canvas.drawRRect(
          RRect.fromRectAndRadius(
            Rect.fromLTWH(
              col * cellWidth + 7,
              row * cellHeight + 7,
              cellWidth - 14,
              cellHeight - 14,
            ),
            const Radius.circular(12),
          ),
          paint,
        );
      }
    }
    paint
      ..color = MCColors.background
      ..style = PaintingStyle.stroke
      ..strokeWidth = 18;
    final road = Path()
      ..moveTo(-10, size.height * .34)
      ..cubicTo(
        size.width * .2,
        size.height * .08,
        size.width * .6,
        size.height * .9,
        size.width + 10,
        size.height * .5,
      );
    canvas.drawPath(road, paint);
    canvas.drawLine(
      Offset(size.width * .49, 0),
      Offset(size.width * .32, size.height),
      paint,
    );
    paint
      ..style = PaintingStyle.fill
      ..color = const Color(0xFFB9CFA4);
    canvas.drawCircle(Offset(size.width * .79, size.height * .28), 22, paint);
    canvas.drawCircle(Offset(size.width * .14, size.height * .83), 14, paint);
  }

  @override
  bool shouldRepaint(covariant _WardArtPainter oldDelegate) => false;
}
