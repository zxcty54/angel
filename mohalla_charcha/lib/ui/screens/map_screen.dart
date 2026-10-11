import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:latlong2/latlong.dart' show LatLng;
import 'package:provider/provider.dart';
import '../../controllers/app_controller.dart';
import '../../models/community.dart';
import '../../models/location.dart';
import '../../theme/app_theme.dart';
import '../widgets/common.dart';

class NeighbourhoodMapScreen extends StatefulWidget {
  const NeighbourhoodMapScreen({super.key, required this.onPost});
  final void Function(CommunityPost) onPost;
  @override
  State<NeighbourhoodMapScreen> createState() => _NeighbourhoodMapScreenState();
}

class _NeighbourhoodMapScreenState extends State<NeighbourhoodMapScreen> {
  List<CommunityPost> _posts = [];
  CommunityPost? _selected;
  PostType? _filter;
  String? _key;
  bool _loading = true;
  bool _online = false;
  String? _error;
  int _request = 0;
  final _map = MapController();
  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final c = context.watch<AppController>();
    final key =
        '${c.selectedLocation!.identity}|${c.scope.name}|${_filter?.key}';
    if (_key != key) {
      _key = key;
      _load();
    }
  }

  Future<void> _load() async {
    final n = ++_request;
    final c = context.read<AppController>();
    setState(() {
      _loading = true;
      _error = null;
      _selected = null;
    });
    try {
      final page = await c.repository.getFeed(
        FeedQuery(
          location: c.selectedLocation!,
          scope: c.scope,
          type: _filter?.key,
          limit: 30,
        ),
      );
      if (!mounted || n != _request) return;
      setState(() {
        _posts = page.posts.where((p) => p.hasCoordinates).toList();
        _loading = false;
      });
    } catch (e) {
      if (mounted && n == _request) {
        setState(() {
          _error = AppController.friendlyError(e);
          _loading = false;
        });
      }
    }
  }

  @override
  void dispose() {
    _map.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    final location = c.selectedLocation!;
    final pins = _posts.map((p) => LatLng(p.latitude!, p.longitude!)).toList();
    return ListView(
      padding: const EdgeInsets.fromLTRB(22, 25, 22, 90),
      children: [
        SectionHeading(
          c.text('नक्शे पर पड़ोस', 'Your neighbourhood, mapped'),
          subtitle: c.text(
            'मुद्दे, दुकानें और कार्यक्रम—एक जगह।',
            'Issues, little favourites and local meet-ups.',
          ),
        ),
        const SizedBox(height: 20),
        Wrap(
          spacing: 7,
          runSpacing: 7,
          children: [
            ChoiceChip(
              label: Text(c.text('सभी', 'All')),
              selected: _filter == null,
              onSelected: (_) {
                setState(() => _filter = null);
                _load();
              },
            ),
            for (final type in PostType.values)
              ChoiceChip(
                avatar: Icon(type.icon, size: 16),
                label: Text(type.label(context)),
                selected: _filter == type,
                onSelected: (_) {
                  setState(() => _filter = type);
                  _load();
                },
              ),
          ],
        ),
        const SizedBox(height: 18),
        Row(
          children: [
            Expanded(
              child: Text(
                _online
                    ? '© OpenStreetMap contributors'
                    : c.text(
                        'ऑफ़लाइन मोहल्ला रूपरेखा',
                        'Offline neighbourhood sketch',
                      ),
                style: const TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  color: MCColors.green,
                ),
              ),
            ),
            TextButton.icon(
              onPressed: () async {
                if (_online) {
                  setState(() => _online = false);
                  return;
                }
                final yes = await showDialog<bool>(
                  context: context,
                  builder: (d) => AlertDialog(
                    title: Text(
                      c.text(
                        'इंटरनेट वाला नक्शा खोलें?',
                        'Open the online map?',
                      ),
                    ),
                    content: Text(
                      c.text(
                        'OpenStreetMap tiles के लिए इंटरनेट लगेगा। आपका IP और देखे गए map tiles provider को दिख सकते हैं। Demo pins नमूना हैं।',
                        'OpenStreetMap tiles need internet. The tile provider can see your IP and requested map area. Demo pins are illustrative.',
                      ),
                    ),
                    actions: [
                      TextButton(
                        onPressed: () => Navigator.pop(d, false),
                        child: Text(c.text('नहीं', 'Not now')),
                      ),
                      FilledButton(
                        onPressed: () => Navigator.pop(d, true),
                        child: Text(c.text('खोलें', 'Open map')),
                      ),
                    ],
                  ),
                );
                if (mounted && yes == true) setState(() => _online = true);
              },
              icon: Icon(_online ? Icons.wifi_off : Icons.public, size: 15),
              label: Text(
                _online
                    ? c.text('ऑफ़लाइन', 'Use sketch')
                    : c.text('Live map', 'Live map'),
                style: const TextStyle(fontSize: 11),
              ),
            ),
          ],
        ),
        const SizedBox(height: 6),
        ClipRRect(
          borderRadius: BorderRadius.circular(20),
          child: SizedBox(
            height: 370,
            child: Stack(
              children: [
                if (_online)
                  FlutterMap(
                    mapController: _map,
                    options: MapOptions(
                      initialCenter: LatLng(
                        location.latitude ?? 25.599,
                        location.longitude ?? 85.158,
                      ),
                      initialZoom: 15,
                      minZoom: 5,
                      maxZoom: 18,
                      initialCameraFit: pins.isEmpty
                          ? null
                          : CameraFit.bounds(
                              bounds: LatLngBounds.fromPoints(pins),
                              padding: const EdgeInsets.all(60),
                              maxZoom: 15,
                            ),
                    ),
                    children: [
                      TileLayer(
                        urlTemplate:
                            'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
                        userAgentPackageName: 'in.mohallacharcha.app',
                        maxNativeZoom: 19,
                        errorTileCallback: (_, _, _) {
                          /* The offline sketch remains available. */
                        },
                      ),
                      MarkerLayer(
                        markers: _posts
                            .map(
                              (p) => Marker(
                                point: LatLng(p.latitude!, p.longitude!),
                                width: 46,
                                height: 52,
                                child: _MapPin(
                                  post: p,
                                  selected: _selected?.id == p.id,
                                  onTap: () => setState(() => _selected = p),
                                ),
                              ),
                            )
                            .toList(),
                      ),
                      const RichAttributionWidget(
                        attributions: [
                          TextSourceAttribution('OpenStreetMap contributors'),
                        ],
                      ),
                    ],
                  )
                else
                  LayoutBuilder(
                    builder: (context, box) {
                      final latitudes = _posts.map((p) => p.latitude!).toList();
                      final longitudes = _posts
                          .map((p) => p.longitude!)
                          .toList();
                      final minLat = latitudes.isEmpty
                          ? 25.595
                          : latitudes.reduce(math.min) - .002;
                      final maxLat = latitudes.isEmpty
                          ? 25.603
                          : latitudes.reduce(math.max) + .002;
                      final minLng = longitudes.isEmpty
                          ? 85.154
                          : longitudes.reduce(math.min) - .002;
                      final maxLng = longitudes.isEmpty
                          ? 85.163
                          : longitudes.reduce(math.max) + .002;
                      return Stack(
                        children: [
                          const Positioned.fill(
                            child: CustomPaint(
                              painter: _NeighbourhoodPainter(),
                            ),
                          ),
                          for (final p in _posts)
                            Positioned(
                              left:
                                  18 +
                                  ((p.longitude! - minLng) /
                                          (maxLng - minLng)) *
                                      (box.maxWidth - 82),
                              top:
                                  24 +
                                  ((maxLat - p.latitude!) / (maxLat - minLat)) *
                                      (box.maxHeight - 104),
                              child: _MapPin(
                                post: p,
                                selected: _selected?.id == p.id,
                                onTap: () => setState(() => _selected = p),
                              ),
                            ),
                        ],
                      );
                    },
                  ),
                if (_loading)
                  const Positioned(
                    top: 12,
                    left: 12,
                    child: Card(
                      child: Padding(
                        padding: EdgeInsets.all(12),
                        child: SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        ),
                      ),
                    ),
                  ),
                if (!_online)
                  Positioned(
                    bottom: 12,
                    left: 12,
                    right: 12,
                    child: Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: Colors.white.withValues(alpha: .9),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        c.text(
                          'केवल रूपरेखा • असली सड़क नक्शा नहीं • पिन लगभग 100m तक गोल हैं',
                          'Illustrative sketch, not a street map • Pins rounded to ~100m',
                        ),
                        textAlign: TextAlign.center,
                        style: const TextStyle(
                          fontSize: 9,
                          color: MCColors.muted,
                        ),
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 18),
        if (_error != null)
          EmptyState(
            title: c.text('पिन लोड नहीं हुए', 'Could not load pins'),
            message: _error!,
            action: _load,
            actionLabel: c.text('फिर कोशिश', 'Retry'),
          )
        else if (_selected != null)
          _MapPostTile(
            post: _selected!,
            onTap: () => widget.onPost(_selected!),
            selected: true,
          )
        else
          Text(
            c.text(
              'किसी पिन को चुनकर उसकी बात पढ़ें।',
              'Tap a pin to see its story.',
            ),
            style: const TextStyle(fontSize: 12, color: MCColors.muted),
          ),
        const SizedBox(height: 24),
        Text(
          c.text(
            'इस इलाके के पिन · ${_posts.length}',
            'Pinned nearby · ${_posts.length}',
          ),
          style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w800),
        ),
        const SizedBox(height: 12),
        if (!_loading && _posts.isEmpty)
          EmptyState(
            title: c.text('यहाँ अभी कोई पिन नहीं', 'No pins here just yet'),
            message: c.text(
              'पता टैग करना वैकल्पिक है। बिना पिन वाली पोस्ट feed में मिलेंगी।',
              'Location pins are optional. Posts without pins still appear in the feed.',
            ),
            icon: Icons.location_off_outlined,
          ),
        for (final p in _posts)
          Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: _MapPostTile(post: p, onTap: () => widget.onPost(p)),
          ),
        const SizedBox(height: 14),
        Text(
          c.text(
            'नक्शे पर अधिकतम 30 हाल की, स्थान-टैग वाली पोस्ट दिखाई जाती हैं।',
            'Map shows location-tagged posts from the latest 30 matching posts.',
          ),
          style: const TextStyle(color: MCColors.muted, fontSize: 10),
        ),
      ],
    );
  }
}

class _MapPin extends StatelessWidget {
  const _MapPin({
    required this.post,
    required this.selected,
    required this.onTap,
  });
  final CommunityPost post;
  final bool selected;
  final VoidCallback onTap;
  @override
  Widget build(BuildContext context) => Semantics(
    label: post.title,
    button: true,
    child: GestureDetector(
      onTap: onTap,
      child: SizedBox(
        width: 46,
        height: 52,
        child: Column(
          children: [
            Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                color: post.isResolved ? MCColors.green : post.type.color,
                shape: BoxShape.circle,
                border: Border.all(
                  color: selected ? MCColors.ink : Colors.white,
                  width: 3,
                ),
                boxShadow: [
                  BoxShadow(
                    color: MCColors.ink.withValues(alpha: .12),
                    blurRadius: 7,
                    offset: const Offset(0, 3),
                  ),
                ],
              ),
              child: Icon(
                post.isResolved ? Icons.check : post.type.icon,
                color: Colors.white,
                size: 20,
              ),
            ),
            Container(width: 3, height: 9, color: post.type.color),
          ],
        ),
      ),
    ),
  );
}

class _MapPostTile extends StatelessWidget {
  const _MapPostTile({
    required this.post,
    required this.onTap,
    this.selected = false,
  });
  final CommunityPost post;
  final VoidCallback onTap;
  final bool selected;
  @override
  Widget build(BuildContext context) => Material(
    color: Colors.white,
    shape: RoundedRectangleBorder(
      borderRadius: BorderRadius.circular(14),
      side: BorderSide(
        color: selected
            ? post.type.color.withValues(alpha: .5)
            : MCColors.border,
      ),
    ),
    child: ListTile(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      onTap: onTap,
      leading: Container(
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: post.type.softColor,
          borderRadius: BorderRadius.circular(10),
        ),
        child: Icon(post.type.icon, color: post.type.color, size: 22),
      ),
      title: Text(
        post.title,
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
        style: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w800,
          height: 1.6,
        ),
      ),
      subtitle: Text(
        '${post.location.shortLabel} · ${post.upvotes} ${tr(context, 'समर्थन', 'votes')}',
        style: const TextStyle(fontSize: 10, color: MCColors.muted),
      ),
      trailing: const Icon(
        Icons.arrow_forward,
        size: 18,
        color: MCColors.muted,
      ),
    ),
  );
}

class _NeighbourhoodPainter extends CustomPainter {
  const _NeighbourhoodPainter();
  @override
  void paint(Canvas canvas, Size size) {
    canvas.drawRect(
      Offset.zero & size,
      Paint()..color = const Color(0xFFE9EDE1),
    );
    final buildings = [
      const Color(0xFFDADFCC),
      const Color(0xFFE4DBCB),
      const Color(0xFFE2E5D6),
      const Color(0xFFDBE7D3),
    ];
    for (var y = 0; y < 5; y++) {
      for (var x = 0; x < 5; x++) {
        final left = x * size.width / 5 + 8;
        final top = y * size.height / 5 + 8;
        final rect = Rect.fromLTWH(
          left,
          top,
          size.width / 5 - 17,
          size.height / 5 - 17,
        );
        canvas.drawRRect(
          RRect.fromRectAndRadius(rect, const Radius.circular(9)),
          Paint()..color = buildings[(x + y) % buildings.length],
        );
        if ((x + y) % 3 == 0) {
          canvas.drawCircle(
            Offset(left + 16, top + 20),
            10,
            Paint()..color = const Color(0xFFBCD2AD),
          );
        }
      }
    }
    final road = Paint()
      ..color = const Color(0xFFF9FAF4)
      ..strokeWidth = 22
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round;
    final path = Path()
      ..moveTo(-20, size.height * .32)
      ..cubicTo(
        size.width * .3,
        size.height * .23,
        size.width * .55,
        size.height * .54,
        size.width + 20,
        size.height * .44,
      );
    canvas.drawPath(path, road);
    final lane = Path()
      ..moveTo(size.width * .42, -20)
      ..cubicTo(
        size.width * .5,
        size.height * .3,
        size.width * .3,
        size.height * .6,
        size.width * .6,
        size.height + 20,
      );
    canvas.drawPath(lane, road..strokeWidth = 19);
    canvas.drawLine(
      Offset(-10, size.height * .8),
      Offset(size.width + 10, size.height * .65),
      road..strokeWidth = 15,
    );
    canvas.drawCircle(
      Offset(size.width * .78, size.height * .2),
      27,
      Paint()..color = const Color(0xFFBBD4AE),
    );
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
