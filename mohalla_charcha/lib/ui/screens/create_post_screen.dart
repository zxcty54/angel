import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:provider/provider.dart';
import '../../controllers/app_controller.dart';
import '../../models/community.dart';
import '../../models/location.dart';
import '../../theme/app_theme.dart';
import '../widgets/common.dart';
import '../widgets/location_picker.dart';

class CreatePostScreen extends StatefulWidget {
  const CreatePostScreen({super.key, this.initialType = PostType.general});
  final PostType initialType;
  @override
  State<CreatePostScreen> createState() => _CreatePostScreenState();
}

class _CreatePostScreenState extends State<CreatePostScreen> {
  final _form = GlobalKey<FormState>();
  final _title = TextEditingController();
  final _description = TextEditingController();
  final _landmark = TextEditingController();
  final _business = TextEditingController();
  final _venue = TextEditingController();
  late PostType _type;
  late AreaPath _location;
  Severity _severity = Severity.medium;
  String _category = 'food';
  double _rating = 4;
  DateTime _date = DateTime.now().add(const Duration(days: 3));
  final List<Uint8List> _images = [];
  bool _pin = false;
  bool _saving = false;
  bool _picking = false;
  bool _allowPop = false;
  @override
  void initState() {
    super.initState();
    _type = widget.initialType;
    _location = context.read<AppController>().selectedLocation!;
    _date = DateTime(_date.year, _date.month, _date.day, 17);
  }

  @override
  void dispose() {
    for (final t in [_title, _description, _landmark, _business, _venue]) {
      t.dispose();
    }
    super.dispose();
  }

  Future<void> _photos() async {
    setState(() => _picking = true);
    try {
      final files = await ImagePicker().pickMultiImage(
        imageQuality: 65,
        maxWidth: 1400,
        maxHeight: 1400,
        limit: 3,
      );
      if (!mounted) return;
      for (final f in files.take(3 - _images.length)) {
        final bytes = await f.readAsBytes();
        if (!mounted) return;
        if (bytes.length > 5 * 1024 * 1024) {
          notifyUser(
            context,
            tr(
              context,
              'हर फ़ोटो 5 MB से छोटी रखें।',
              'Each photo must be under 5 MB.',
            ),
          );
          continue;
        }
        final valid =
            bytes.length > 12 &&
            ((bytes[0] == 255 && bytes[1] == 216) ||
                (bytes[0] == 137 && bytes[1] == 80) ||
                (bytes[0] == 82 && bytes[1] == 73 && bytes[8] == 87));
        if (!valid) {
          notifyUser(
            context,
            tr(
              context,
              'JPEG, PNG या WebP फ़ोटो चुनें।',
              'Choose a JPEG, PNG or WebP photo.',
            ),
          );
          continue;
        }
        setState(() => _images.add(bytes));
      }
    } catch (e) {
      if (mounted) notifyUser(context, AppController.friendlyError(e));
    } finally {
      if (mounted) setState(() => _picking = false);
    }
  }

  Future<void> _pickDate() async {
    final now = DateTime.now();
    final day = await showDatePicker(
      context: context,
      initialDate: _date,
      firstDate: DateTime(now.year, now.month, now.day),
      lastDate: now.add(const Duration(days: 730)),
    );
    if (day == null || !mounted) return;
    final time = await showTimePicker(
      context: context,
      initialTime: TimeOfDay.fromDateTime(_date),
    );
    if (time == null || !mounted) return;
    setState(
      () => _date = DateTime(
        day.year,
        day.month,
        day.day,
        time.hour,
        time.minute,
      ),
    );
  }

  Future<void> _submit() async {
    if (!_form.currentState!.validate() || _saving) return;
    setState(() => _saving = true);
    try {
      final metadata = switch (_type) {
        PostType.civicIssue => IssueMetadata(severity: _severity),
        PostType.localReview => ReviewMetadata(
          businessName: _business.text.trim(),
          category: _category,
          rating: _rating,
        ),
        PostType.event => EventMetadata(
          date: _date.toUtc(),
          venue: _venue.text.trim(),
        ),
        PostType.general => const GeneralMetadata(),
      };
      final post = await context.read<AppController>().publish(
        PostDraft(
          type: _type,
          title: _title.text,
          description: _description.text,
          location: _location,
          metadata: metadata,
          landmark: _landmark.text,
          images: _images,
          latitude: _pin ? _location.latitude : null,
          longitude: _pin ? _location.longitude : null,
        ),
      );
      if (!mounted) return;
      setState(() {
        _allowPop = true;
        _saving = false;
      });
      await WidgetsBinding.instance.endOfFrame;
      if (mounted) Navigator.pop(context, post);
    } catch (e) {
      if (mounted) notifyUser(context, AppController.friendlyError(e));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<bool> _confirmExit() async {
    if (_saving) return false;
    if (_title.text.isEmpty && _description.text.isEmpty && _images.isEmpty) {
      return true;
    }
    return await showDialog<bool>(
          context: context,
          builder: (d) => AlertDialog(
            title: Text(
              tr(context, 'अधूरी पोस्ट छोड़ें?', 'Discard this draft?'),
            ),
            content: Text(
              tr(
                context,
                'अभी लिखा हुआ मसौदा सेव नहीं होगा।',
                'Your unsent draft will not be saved.',
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(d, false),
                child: Text(tr(context, 'लिखते रहें', 'Keep writing')),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(d, true),
                child: Text(tr(context, 'छोड़ें', 'Discard')),
              ),
            ],
          ),
        ) ??
        false;
  }

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    return PopScope(
      canPop:
          _allowPop ||
          (!_saving &&
              _title.text.isEmpty &&
              _description.text.isEmpty &&
              _images.isEmpty),
      onPopInvokedWithResult: (didPop, result) async {
        if (didPop) return;
        if (await _confirmExit() && mounted) {
          setState(() => _allowPop = true);
          await WidgetsBinding.instance.endOfFrame;
          if (context.mounted) Navigator.pop(context);
        }
      },
      child: Scaffold(
        appBar: AppBar(
          title: Text(
            c.text('मोहल्ले में बात रखें', 'Share with your neighbourhood'),
            style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w800),
          ),
        ),
        body: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 680),
            child: Form(
              key: _form,
              child: ListView(
                padding: const EdgeInsets.all(22),
                children: [
                  Text(
                    c.text(
                      'आपकी आवाज़ मायने रखती है।',
                      'Your local voice matters.',
                    ),
                    style: const TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                  const SizedBox(height: 7),
                  Text(
                    c.text(
                      'एक पोस्ट—समस्या, समीक्षा, कार्यक्रम या सीधी-सी बात।',
                      'One post. An issue, a review, an event or a simple hello.',
                    ),
                    style: const TextStyle(
                      fontSize: 12,
                      color: MCColors.muted,
                      height: 1.7,
                    ),
                  ),
                  const SizedBox(height: 22),
                  Text(
                    c.text('किस तरह की बात?', 'What are you sharing?'),
                    style: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                  const SizedBox(height: 10),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: PostType.values
                        .map(
                          (type) => ChoiceChip(
                            label: Text(
                              type.label(context),
                              style: const TextStyle(fontSize: 12),
                            ),
                            avatar: Icon(type.icon, size: 17),
                            selected: _type == type,
                            onSelected: _saving
                                ? null
                                : (_) => setState(() => _type = type),
                          ),
                        )
                        .toList(),
                  ),
                  const SizedBox(height: 22),
                  ListTile(
                    contentPadding: const EdgeInsets.symmetric(
                      horizontal: 15,
                      vertical: 3,
                    ),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(14),
                      side: const BorderSide(color: MCColors.border),
                    ),
                    tileColor: Colors.white,
                    leading: const Icon(
                      Icons.location_on_outlined,
                      color: MCColors.primary,
                    ),
                    title: Text(
                      '${_location.shortLabel} · Ward ${_location.ward}',
                      style: const TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    subtitle: Text(
                      _location.fullLabel,
                      style: const TextStyle(
                        color: MCColors.muted,
                        fontSize: 10,
                      ),
                    ),
                    trailing: const Icon(Icons.keyboard_arrow_down),
                    onTap: _saving
                        ? null
                        : () async {
                            final area = await pickArea(
                              context,
                              initial: _location,
                            );
                            if (area != null && mounted) {
                              setState(() {
                                _location = area;
                                _pin = false;
                              });
                            }
                          },
                  ),
                  const SizedBox(height: 20),
                  TextFormField(
                    controller: _title,
                    enabled: !_saving,
                    maxLength: 200,
                    decoration: InputDecoration(
                      labelText: c.text('शीर्षक', 'Title'),
                      hintText: c.text('क्या हो रहा है?', 'What’s happening?'),
                    ),
                    onChanged: (_) => setState(() {}),
                    validator: (s) => (s?.trim().length ?? 0) < 5
                        ? c.text(
                            'कम से कम 5 अक्षर लिखें।',
                            'Write at least 5 characters.',
                          )
                        : null,
                  ),
                  const SizedBox(height: 12),
                  TextFormField(
                    controller: _description,
                    enabled: !_saving,
                    maxLength: 5000,
                    minLines: 4,
                    maxLines: 8,
                    decoration: InputDecoration(
                      labelText: c.text(
                        'थोड़ा विस्तार से',
                        'Tell us a little more',
                      ),
                      alignLabelWithHint: true,
                      hintText: c.text(
                        'क्या, कहाँ और पड़ोसी कैसे साथ दे सकते हैं…',
                        'What, where, and how neighbours can help…',
                      ),
                    ),
                    onChanged: (_) => setState(() {}),
                    validator: (s) => (s?.trim().length ?? 0) < 10
                        ? c.text(
                            'कम से कम 10 अक्षर लिखें।',
                            'Write at least 10 characters.',
                          )
                        : null,
                  ),
                  if (_type == PostType.civicIssue) ...[
                    const SizedBox(height: 14),
                    Text(
                      c.text(
                        'इसका कितना असर है?',
                        'How much is this affecting people?',
                      ),
                      style: const TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    const SizedBox(height: 10),
                    SizedBox(
                      width: double.infinity,
                      child: SegmentedButton<Severity>(
                        segments: [
                          ButtonSegment(
                            value: Severity.low,
                            label: Text(c.text('कम', 'Low')),
                          ),
                          ButtonSegment(
                            value: Severity.medium,
                            label: Text(c.text('मध्यम', 'Medium')),
                          ),
                          ButtonSegment(
                            value: Severity.high,
                            label: Text(c.text('ज़्यादा', 'High')),
                          ),
                        ],
                        selected: {_severity},
                        onSelectionChanged: _saving
                            ? null
                            : (v) => setState(() => _severity = v.first),
                      ),
                    ),
                  ],
                  if (_type == PostType.localReview) ...[
                    const SizedBox(height: 16),
                    TextFormField(
                      controller: _business,
                      enabled: !_saving,
                      maxLength: 120,
                      decoration: InputDecoration(
                        labelText: c.text(
                          'दुकान / जगह का नाम',
                          'Shop or place name',
                        ),
                      ),
                      validator: (s) => (s?.trim().isEmpty ?? true)
                          ? c.text('जगह का नाम लिखें।', 'Enter the place name.')
                          : null,
                    ),
                    const SizedBox(height: 12),
                    DropdownButtonFormField<String>(
                      initialValue: _category,
                      decoration: InputDecoration(
                        labelText: c.text('श्रेणी', 'Category'),
                      ),
                      items: [
                        for (final pair in [
                          ('food', 'खाना और चाय', 'Food & tea'),
                          ('grocery', 'किराना', 'Groceries'),
                          ('services', 'स्थानीय सेवाएँ', 'Local services'),
                          ('health', 'स्वास्थ्य', 'Health'),
                          ('education', 'शिक्षा', 'Education'),
                          ('other', 'अन्य', 'Other'),
                        ])
                          DropdownMenuItem(
                            value: pair.$1,
                            child: Text(c.text(pair.$2, pair.$3)),
                          ),
                      ],
                      onChanged: _saving
                          ? null
                          : (v) => setState(() => _category = v!),
                    ),
                    const SizedBox(height: 14),
                    Row(
                      children: [
                        Text(
                          c.text('आपकी रेटिंग', 'Your rating'),
                          style: const TextStyle(
                            fontSize: 12,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                        const Spacer(),
                        const Icon(
                          Icons.star_rounded,
                          color: MCColors.amber,
                          size: 21,
                        ),
                        Text(
                          ' ${_rating.toStringAsFixed(1)} / 5',
                          style: const TextStyle(fontWeight: FontWeight.w800),
                        ),
                      ],
                    ),
                    Slider(
                      value: _rating,
                      min: 1,
                      max: 5,
                      divisions: 8,
                      label: _rating.toStringAsFixed(1),
                      activeColor: MCColors.amber,
                      onChanged: _saving
                          ? null
                          : (v) => setState(() => _rating = v),
                    ),
                  ],
                  if (_type == PostType.event) ...[
                    const SizedBox(height: 16),
                    TextFormField(
                      controller: _venue,
                      enabled: !_saving,
                      maxLength: 150,
                      decoration: InputDecoration(
                        labelText: c.text('मिलने की जगह', 'Venue'),
                      ),
                      validator: (s) => (s?.trim().isEmpty ?? true)
                          ? c.text(
                              'सार्वजनिक जगह लिखें।',
                              'Enter a public meeting place.',
                            )
                          : null,
                    ),
                    const SizedBox(height: 10),
                    OutlinedButton.icon(
                      onPressed: _saving ? null : _pickDate,
                      icon: const Icon(Icons.calendar_month_outlined, size: 18),
                      label: Text(eventDate(context, _date.toUtc())),
                    ),
                    const SizedBox(height: 5),
                    Text(
                      c.text(
                        'समय आपके डिवाइस के timezone में दिखता है; server पर UTC में सेव होगा।',
                        'Shown in your device timezone; stored as UTC on the server.',
                      ),
                      style: const TextStyle(
                        fontSize: 10,
                        color: MCColors.muted,
                      ),
                    ),
                  ],
                  const SizedBox(height: 20),
                  TextFormField(
                    controller: _landmark,
                    enabled: !_saving,
                    maxLength: 150,
                    decoration: InputDecoration(
                      labelText: c.text(
                        'नज़दीकी पहचान (वैकल्पिक)',
                        'Nearby landmark (optional)',
                      ),
                      hintText: c.text(
                        'जैसे: पार्क के पास—पूरा घर का पता नहीं',
                        'e.g. near the park—not your full address',
                      ),
                    ),
                  ),
                  const SizedBox(height: 10),
                  SwitchListTile.adaptive(
                    contentPadding: EdgeInsets.zero,
                    value: _pin,
                    onChanged: _saving || _location.latitude == null
                        ? null
                        : (v) => setState(() => _pin = v),
                    title: Text(
                      c.text(
                        'मोहल्ले के केंद्र के पास पिन लगाएँ',
                        'Pin near the neighbourhood centre',
                      ),
                      style: const TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    subtitle: Text(
                      c.text(
                        'सिर्फ़ लगभग इलाका। GPS या घर का पता नहीं लिया जाता।',
                        'Approximate area only. We do not collect GPS or your home address.',
                      ),
                      style: const TextStyle(
                        fontSize: 10,
                        color: MCColors.muted,
                        height: 1.6,
                      ),
                    ),
                  ),
                  const SizedBox(height: 14),
                  Row(
                    children: [
                      Text(
                        c.text(
                          'फ़ोटो · ${_images.length}/3',
                          'Photos · ${_images.length}/3',
                        ),
                        style: const TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                      const Spacer(),
                      Text(
                        c.isDemo
                            ? c.text('Demo: कुल 1.5 MB', 'Demo: 1.5 MB total')
                            : c.text(
                                'अधिकतम 5 MB / फ़ोटो',
                                'Max. 5 MB / photo',
                              ),
                        style: const TextStyle(
                          fontSize: 10,
                          color: MCColors.muted,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Wrap(
                    spacing: 10,
                    runSpacing: 10,
                    children: [
                      for (var i = 0; i < _images.length; i++)
                        Stack(
                          children: [
                            ClipRRect(
                              borderRadius: BorderRadius.circular(12),
                              child: Image.memory(
                                _images[i],
                                width: 92,
                                height: 92,
                                fit: BoxFit.cover,
                              ),
                            ),
                            Positioned(
                              top: 1,
                              right: 1,
                              child: IconButton.filled(
                                onPressed: _saving
                                    ? null
                                    : () => setState(() => _images.removeAt(i)),
                                icon: const Icon(Icons.close, size: 15),
                                constraints: const BoxConstraints.tightFor(
                                  width: 28,
                                  height: 28,
                                ),
                                padding: EdgeInsets.zero,
                                tooltip: c.text('फ़ोटो हटाएँ', 'Remove photo'),
                              ),
                            ),
                          ],
                        ),
                      if (_images.length < 3)
                        SizedBox(
                          width: 92,
                          height: 92,
                          child: OutlinedButton(
                            onPressed: _saving || _picking ? null : _photos,
                            style: OutlinedButton.styleFrom(
                              padding: EdgeInsets.zero,
                            ),
                            child: _picking
                                ? const SizedBox(
                                    width: 20,
                                    height: 20,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                    ),
                                  )
                                : const Icon(
                                    Icons.add_photo_alternate_outlined,
                                    size: 27,
                                  ),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 22),
                  Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: MCColors.greenSoft,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Icon(
                          Icons.shield_outlined,
                          color: MCColors.green,
                          size: 18,
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            c.text(
                              'सम्मान से लिखें। निजी जानकारी साझा न करें। यह पोस्ट पड़ोसियों के लिए है—किसी सरकारी विभाग को नहीं भेजी जाएगी।',
                              'Be kind. Keep personal information private. This goes to neighbours—not to any government department.',
                            ),
                            style: const TextStyle(
                              color: MCColors.green,
                              fontSize: 11,
                              height: 1.7,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 22),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      onPressed: _saving ? null : _submit,
                      icon: _saving
                          ? const SizedBox(
                              width: 17,
                              height: 17,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                color: Colors.white,
                              ),
                            )
                          : const Icon(Icons.send_outlined, size: 18),
                      label: Text(
                        _saving
                            ? c.text('पोस्ट भेज रहे हैं…', 'Sharing…')
                            : c.text(
                                'मोहल्ले में साझा करें',
                                'Share with your neighbourhood',
                              ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 25),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
