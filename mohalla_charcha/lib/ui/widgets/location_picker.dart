import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../controllers/app_controller.dart';
import '../../data/location_catalogue.dart';
import '../../models/location.dart';
import '../../theme/app_theme.dart';
import 'common.dart';

Future<AreaPath?> pickArea(BuildContext context, {AreaPath? initial}) =>
    showModalBottomSheet<AreaPath>(
      context: context,
      isScrollControlled: true,
      useSafeArea: true,
      constraints: const BoxConstraints(maxWidth: 600),
      builder: (_) => LocationPicker(
        initial: initial ?? context.read<AppController>().selectedLocation,
      ),
    );

class LocationPicker extends StatefulWidget {
  const LocationPicker({super.key, this.initial});
  final AreaPath? initial;
  @override
  State<LocationPicker> createState() => _LocationPickerState();
}

class _LocationPickerState extends State<LocationPicker> {
  late String _district;
  late AreaType _type;
  String? _ulb;
  String? _panchayat;
  int? _wardId;
  List<AreaPath> _rows = [];
  bool _loading = true;
  String? _error;
  int _request = 0;
  @override
  void initState() {
    super.initState();
    final a = widget.initial;
    _district = a?.district ?? 'Patna';
    _type = a?.areaType ?? AreaType.urban;
    _ulb = a?.blockOrUlb;
    _panchayat = a?.panchayat;
    _wardId = a?.id;
    _load();
  }

  Future<void> _load() async {
    final request = ++_request;
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final rows = await context.read<AppController>().locationsFor(_district);
      if (!mounted || request != _request) return;
      setState(() {
        _rows = rows;
        _loading = false;
      });
    } catch (e) {
      if (mounted && request == _request) {
        setState(() {
          _error = AppController.friendlyError(e);
          _loading = false;
        });
      }
    }
  }

  List<AreaPath> get _typed => _rows.where((r) => r.areaType == _type).toList();
  List<AreaPath> get _wards => _typed
      .where(
        (r) =>
            r.blockOrUlb == _ulb &&
            (!_type.isRural || r.panchayat == _panchayat),
      )
      .toList();

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    final ulbs = _typed.map((r) => r.blockOrUlb).toSet().toList()..sort();
    final panchayats =
        _typed
            .where((r) => r.blockOrUlb == _ulb)
            .map((r) => r.panchayat)
            .whereType<String>()
            .toSet()
            .toList()
          ..sort();
    AreaPath? selected;
    for (final a in _wards) {
      if (a.id == _wardId) selected = a;
    }
    return Padding(
      padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom),
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(24, 0, 24, 28),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Row(
              children: [
                const Icon(Icons.location_on_outlined, color: MCColors.primary),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    c.text('अपना इलाका चुनें', 'Find your neighbourhood'),
                    style: const TextStyle(
                      fontSize: 21,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ),
                IconButton(
                  onPressed: () => Navigator.pop(context),
                  icon: const Icon(Icons.close),
                  tooltip: c.text('बंद करें', 'Close'),
                ),
              ],
            ),
            const SizedBox(height: 4),
            Text(
              c.text(
                'पहले अपना वार्ड, फिर आसपास की बात।',
                'Your ward first. The wider community next.',
              ),
              style: const TextStyle(color: MCColors.muted, fontSize: 13),
            ),
            const SizedBox(height: 22),
            DropdownButtonFormField<String>(
              key: ValueKey('district-$_district'),
              initialValue: _district,
              isExpanded: true,
              decoration: InputDecoration(
                labelText: c.text('ज़िला', 'District'),
              ),
              items: biharDistricts
                  .map((d) => DropdownMenuItem(value: d, child: Text(d)))
                  .toList(),
              onChanged: (d) {
                if (d == null) return;
                setState(() {
                  _district = d;
                  _ulb = null;
                  _panchayat = null;
                  _wardId = null;
                });
                _load();
              },
            ),
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              child: SegmentedButton<AreaType>(
                segments: [
                  ButtonSegment(
                    value: AreaType.urban,
                    icon: const Icon(Icons.apartment),
                    label: Text(c.text('शहरी', 'Urban')),
                  ),
                  ButtonSegment(
                    value: AreaType.rural,
                    icon: const Icon(Icons.cottage_outlined),
                    label: Text(c.text('ग्रामीण', 'Rural')),
                  ),
                ],
                selected: {_type},
                onSelectionChanged: (v) => setState(() {
                  _type = v.first;
                  _ulb = null;
                  _panchayat = null;
                  _wardId = null;
                }),
              ),
            ),
            const SizedBox(height: 16),
            if (_loading)
              const Padding(
                padding: EdgeInsets.all(26),
                child: Center(child: CircularProgressIndicator(strokeWidth: 2)),
              )
            else if (_error != null)
              EmptyState(
                title: c.text('इलाका लोड नहीं हुआ', 'Could not load locations'),
                message: _error!,
                action: _load,
                actionLabel: c.text('फिर कोशिश करें', 'Retry'),
              )
            else if (_typed.isEmpty)
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: MCColors.amberSoft,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  c.isDemo
                      ? c.text(
                          'इस ज़िले/क्षेत्र के demo वार्ड अभी शामिल नहीं हैं। Patna में शहरी और ग्रामीण दोनों नमूने देखें।',
                          'This district/area has no demo wards yet. Patna includes both urban and rural samples.',
                        )
                      : c.text(
                          'यहाँ verified ward data अभी जोड़ा नहीं गया है। दूसरा इलाका चुनें।',
                          'No verified ward data has been imported here yet. Choose another area.',
                        ),
                  style: const TextStyle(fontSize: 13, height: 1.6),
                ),
              )
            else ...[
              DropdownButtonFormField<String>(
                key: ValueKey('ulb-$_district-${_type.name}-$_ulb'),
                initialValue: ulbs.contains(_ulb) ? _ulb : null,
                isExpanded: true,
                decoration: InputDecoration(
                  labelText: c.text(
                    _type.isRural ? 'प्रखंड / Block' : 'नगर निकाय / ULB',
                    _type.isRural ? 'Block / Prakhand' : 'Urban local body',
                  ),
                ),
                items: ulbs
                    .map(
                      (d) => DropdownMenuItem(
                        value: d,
                        child: Text(d, overflow: TextOverflow.ellipsis),
                      ),
                    )
                    .toList(),
                onChanged: (d) => setState(() {
                  _ulb = d;
                  _panchayat = null;
                  _wardId = null;
                }),
              ),
              if (_type.isRural) ...[
                const SizedBox(height: 16),
                DropdownButtonFormField<String>(
                  key: ValueKey('panchayat-$_ulb-$_panchayat'),
                  initialValue: panchayats.contains(_panchayat)
                      ? _panchayat
                      : null,
                  isExpanded: true,
                  decoration: InputDecoration(
                    labelText: c.text('ग्राम पंचायत', 'Gram panchayat'),
                  ),
                  items: panchayats
                      .map((d) => DropdownMenuItem(value: d, child: Text(d)))
                      .toList(),
                  onChanged: _ulb == null
                      ? null
                      : (d) => setState(() {
                          _panchayat = d;
                          _wardId = null;
                        }),
                ),
              ],
              const SizedBox(height: 16),
              DropdownButtonFormField<int>(
                key: ValueKey('ward-$_district-$_ulb-$_panchayat-$_wardId'),
                initialValue: selected?.id,
                isExpanded: true,
                decoration: InputDecoration(
                  labelText: c.text('वार्ड / मोहल्ला', 'Ward / neighbourhood'),
                ),
                items: _wards
                    .map(
                      (a) => DropdownMenuItem(
                        value: a.id,
                        child: Text(
                          'Ward ${a.ward} · ${a.shortLabel}',
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    )
                    .toList(),
                onChanged: _wards.isEmpty
                    ? null
                    : (id) => setState(() => _wardId = id),
              ),
            ],
            const SizedBox(height: 18),
            if (c.isDemo)
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(
                    Icons.info_outline,
                    size: 16,
                    color: MCColors.muted,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      c.text(
                        'वार्ड–मोहल्ला संबंध नमूना हैं, आधिकारिक सीमा डेटा नहीं।',
                        'Demo ward mappings are illustrative, not official boundary data.',
                      ),
                      style: const TextStyle(
                        color: MCColors.muted,
                        fontSize: 11,
                        height: 1.5,
                      ),
                    ),
                  ),
                ],
              ),
            const SizedBox(height: 22),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: selected == null || _loading
                    ? null
                    : () => Navigator.pop(context, selected),
                icon: const Icon(Icons.check, size: 18),
                label: Text(
                  c.text('यह इलाका चुनें', 'Choose this neighbourhood'),
                ),
              ),
            ),
            const SizedBox(height: 10),
            Center(
              child: Text(
                c.text(
                  'घर का इलाका प्रोफ़ाइल से बदला जा सकता है।',
                  'Your home ward can be changed from your profile.',
                ),
                style: const TextStyle(fontSize: 10, color: MCColors.muted),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

extension on AreaType {
  bool get isRural => this == AreaType.rural;
}
