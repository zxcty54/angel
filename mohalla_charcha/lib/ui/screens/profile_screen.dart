import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../controllers/app_controller.dart';
import '../../models/community.dart';
import '../../models/location.dart';
import '../../repositories/demo_repository.dart';
import '../../theme/app_theme.dart';
import '../../config/app_identity.dart';
import '../widgets/common.dart';
import '../widgets/location_picker.dart';
import '../widgets/post_card.dart';
import 'welcome_screen.dart';

class ProfileScreen extends StatefulWidget {
  const ProfileScreen({super.key, required this.onPost});
  final void Function(CommunityPost) onPost;
  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  bool _saved = false;
  late Future<List<CommunityPost>> _items;
  @override
  void initState() {
    super.initState();
    _reload();
  }

  void _reload() {
    final c = context.read<AppController>();
    _items = _saved ? c.savedPosts() : c.repository.getMyPosts();
  }

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    final p = c.profile!;
    return ListView(
      padding: const EdgeInsets.fromLTRB(22, 26, 22, 90),
      children: [
        SectionHeading(
          c.text('आप, इस मोहल्ले का हिस्सा', 'You belong here.'),
          subtitle: c.text(
            'आपका घर का इलाका और आपकी बातें।',
            'Your home ward. Your little corner of the community.',
          ),
        ),
        const SizedBox(height: 22),
        Container(
          padding: const EdgeInsets.all(22),
          decoration: BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: MCColors.border),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  ProfileAvatar(p, size: 68),
                  const SizedBox(width: 15),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          p.name,
                          style: const TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                        const SizedBox(height: 6),
                        LabelPill(
                          text: c.isDemo
                              ? c.text('Demo पड़ोसी', 'Demo neighbour')
                              : c.text('गेस्ट पड़ोसी', 'Guest neighbour'),
                          icon: c.isDemo
                              ? Icons.person_outline
                              : Icons.verified_user_outlined,
                          small: true,
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 20),
              const Divider(),
              const SizedBox(height: 17),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(
                    Icons.home_outlined,
                    size: 20,
                    color: MCColors.green,
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          c.text('घर का इलाका', 'Home neighbourhood'),
                          style: const TextStyle(
                            color: MCColors.muted,
                            fontSize: 10,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          '${p.location.shortLabel} · Ward ${p.location.ward}',
                          style: const TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                        const SizedBox(height: 3),
                        Text(
                          p.location.fullLabel,
                          style: const TextStyle(
                            fontSize: 10,
                            color: MCColors.muted,
                            height: 1.6,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 14),
              Wrap(
                crossAxisAlignment: WrapCrossAlignment.center,
                spacing: 6,
                runSpacing: 6,
                children: [
                  const Icon(
                    Icons.workspace_premium_outlined,
                    size: 19,
                    color: MCColors.amber,
                  ),
                  const SizedBox(width: 10),
                  Text(
                    '${p.reputation} ${c.text('समुदाय प्रतिष्ठा', 'community reputation')}',
                    style: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  if (c.isDemo)
                    Text(
                      c.text(' · नमूना', ' · sample'),
                      style: const TextStyle(
                        fontSize: 10,
                        color: MCColors.muted,
                      ),
                    ),
                ],
              ),
              const SizedBox(height: 18),
              SizedBox(
                width: double.infinity,
                child: OutlinedButton.icon(
                  onPressed: () async {
                    await editProfile(context);
                    if (mounted) setState(_reload);
                  },
                  icon: const Icon(Icons.edit_outlined, size: 17),
                  label: Text(c.text('प्रोफ़ाइल बदलें', 'Edit your profile')),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
          decoration: BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: MCColors.border),
          ),
          child: Column(
            children: [
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(
                  Icons.translate_outlined,
                  color: MCColors.green,
                ),
                title: Text(
                  c.text('भाषा', 'Language'),
                  style: const TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                trailing: TextButton(
                  onPressed: () => safeAction(context, c.toggleLanguage),
                  child: Text(c.isHindi ? 'English' : 'हिन्दी'),
                ),
              ),
              const Divider(),
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(
                  Icons.privacy_tip_outlined,
                  color: MCColors.green,
                ),
                title: Text(
                  c.text(
                    'निजता और समुदाय नियम',
                    'Privacy & community guidelines',
                  ),
                  style: const TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                trailing: const Icon(Icons.chevron_right, size: 20),
                onTap: () => _privacy(context),
              ),
              const Divider(),
              ListTile(
                key: const Key('replay_welcome'),
                contentPadding: EdgeInsets.zero,
                leading: const Icon(
                  Icons.waving_hand_outlined,
                  color: MCColors.green,
                ),
                title: Text(
                  c.text('ऐप कैसे चलाएँ', 'Welcome & app tour'),
                  style: const TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                trailing: const Icon(Icons.chevron_right, size: 20),
                onTap: () => Navigator.of(context).push(
                  MaterialPageRoute<void>(
                    builder: (_) => const WelcomeScreen(replay: true),
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: MCColors.amberSoft,
            borderRadius: BorderRadius.circular(14),
          ),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Icon(Icons.info_outline, color: MCColors.amber, size: 19),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  c.isDemo
                      ? c.text(
                          'यह local demo है। पोस्ट, प्रतिक्रिया और जवाब इस device/browser में सेव होते हैं। कोई असली SMS नहीं भेजा जाता।',
                          'This is a local demo. Posts, reactions and replies stay on this device/browser. No real SMS is sent.',
                        )
                      : c.text(
                          'गेस्ट खाता निवास सत्यापित नहीं करता। सभी पोस्ट community P2P हैं; सरकारी सिस्टम से कोई जुड़ाव नहीं।',
                          'A guest account does not verify residency. All posts are community P2P; there is no government integration.',
                        ),
                  style: const TextStyle(
                    color: MCColors.amber,
                    fontSize: 11,
                    height: 1.7,
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),
        SizedBox(
          width: double.infinity,
          child: SegmentedButton<bool>(
            segments: [
              ButtonSegment(
                value: false,
                icon: const Icon(Icons.article_outlined, size: 18),
                label: Text(c.text('मेरी पोस्ट', 'My posts')),
              ),
              ButtonSegment(
                value: true,
                icon: const Icon(Icons.bookmark_border, size: 18),
                label: Text(c.text('सहेजी हुई', 'Saved')),
              ),
            ],
            selected: {_saved},
            onSelectionChanged: (v) => setState(() {
              _saved = v.first;
              _reload();
            }),
          ),
        ),
        const SizedBox(height: 18),
        FutureBuilder<List<CommunityPost>>(
          future: _items,
          builder: (context, s) {
            if (s.hasError) {
              return EmptyState(
                title: c.text('पोस्ट लोड नहीं हुईं', 'Could not load posts'),
                message: AppController.friendlyError(s.error!),
                action: () => setState(_reload),
                actionLabel: c.text('फिर कोशिश', 'Retry'),
              );
            }
            if (!s.hasData) {
              return const Padding(
                padding: EdgeInsets.all(30),
                child: Center(child: CircularProgressIndicator(strokeWidth: 2)),
              );
            }
            final list = _saved
                ? s.data!.where((p) => c.isSaved(p.id)).toList()
                : s.data!;
            if (list.isEmpty) {
              return EmptyState(
                title: _saved
                    ? c.text(
                        'काम की बातें यहाँ रखें',
                        'Keep good local finds here',
                      )
                    : c.text(
                        'अपनी पहली बात रखें',
                        'Share your first local story',
                      ),
                message: _saved
                    ? c.text(
                        'बुकमार्क दबाकर पोस्ट बाद के लिए सहेजें।',
                        'Tap the bookmark on a post to save it for later.',
                      )
                    : c.text(
                        'अपनी समस्या, समीक्षा, कार्यक्रम या विचार मोहल्ले में साझा करें।',
                        'Your ideas, issues, reviews and plans belong in the neighbourhood.',
                      ),
              );
            }
            return Column(
              children: list
                  .map(
                    (post) => Padding(
                      padding: const EdgeInsets.only(bottom: 16),
                      child: PostCard(
                        post: post,
                        onOpen: () => widget.onPost(post),
                        onDeleted: () => setState(_reload),
                      ),
                    ),
                  )
                  .toList(),
            );
          },
        ),
        const SizedBox(height: 20),
        if (c.isDemo)
          TextButton.icon(
            onPressed: () async {
              final yes = await showDialog<bool>(
                context: context,
                builder: (d) => AlertDialog(
                  title: Text(
                    c.text('Demo फिर से शुरू करें?', 'Reset the demo?'),
                  ),
                  content: Text(
                    c.text(
                      'इस device की बनाई पोस्ट, जवाब और प्रतिक्रियाएँ मिट जाएँगी।',
                      'Local posts, replies and reaction changes will be removed.',
                    ),
                  ),
                  actions: [
                    TextButton(
                      onPressed: () => Navigator.pop(d, false),
                      child: Text(c.text('नहीं', 'Cancel')),
                    ),
                    FilledButton(
                      onPressed: () => Navigator.pop(d, true),
                      child: Text(c.text('रीसेट', 'Reset')),
                    ),
                  ],
                ),
              );
              if (yes == true && context.mounted) {
                await safeAction(context, () async {
                  await (c.repository as DemoRepository).reset();
                  await c.reloadSession();
                  if (mounted) setState(_reload);
                });
              }
            },
            icon: const Icon(Icons.restart_alt, size: 18),
            label: Text(c.text('Demo रीसेट करें', 'Reset demo data')),
          )
        else
          OutlinedButton.icon(
            onPressed: () => safeAction(context, c.signOut),
            icon: const Icon(Icons.logout, size: 18),
            label: Text(c.text('लॉग आउट', 'Sign out')),
          ),
        const SizedBox(height: 12),
        Center(
          child: Text(
            '${AppIdentity.displayName} · ${AppIdentity.version}\nMade for Bihar. Built around people.',
            textAlign: TextAlign.center,
            style: const TextStyle(
              color: MCColors.muted,
              fontSize: 10,
              height: 1.8,
            ),
          ),
        ),
      ],
    );
  }

  void _privacy(BuildContext context) {
    final c = context.read<AppController>();
    showDialog<void>(
      context: context,
      builder: (d) => AlertDialog(
        title: Text(c.text('निजता और भरोसा', 'Privacy & trust')),
        content: SingleChildScrollView(
          child: Text(
            c.text(
              '• Live mode किसी मोबाइल नंबर या OTP के बिना गेस्ट सत्र उपयोग करता है। app data मिटने/रीसेट पर वही guest खाता मिलता है।\n\n• वार्ड और वैकल्पिक landmark साझा किए जाते हैं। पूरा घर का पता न लिखें।\n\n• GPS नहीं लिया जाता। पिन लगभग 100m तक गोल रखे जाते हैं।\n\n• फ़ोटो से पहचान या metadata leak हो सकती है। संवेदनशील तस्वीर न साझा करें।\n\n• रिपोर्ट community moderation के लिए है; किसी अधिकारी को नहीं भेजी जाती।\n\n• Demo डेटा इसी browser/device में रहता है। रीसेट से इसे हटाया जा सकता है।\n\n• Live account deletion के लिए project operator से संपर्क करें। लॉन्च से पहले operator की contact/privacy policy जोड़ना ज़रूरी है।',
              '• Live mode uses an anonymous guest session — no phone number or OTP. Clearing app data loses that guest account.\n\n• Your ward and optional landmark are shared. Do not write an exact home address.\n\n• GPS is not collected. Coordinates are rounded to roughly 100m.\n\n• Photos may reveal identity or metadata. Never share sensitive images.\n\n• Reports are community moderation, not official complaints.\n\n• Demo data stays on this browser/device and can be reset.\n\n• Live account deletion requires the project operator. Add operator contact details and a reviewed privacy policy before launch.',
            ),
            style: const TextStyle(fontSize: 12, height: 1.7),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(d),
            child: Text(c.text('समझ गया', 'Got it')),
          ),
        ],
      ),
    );
  }
}

Future<void> editProfile(BuildContext context) => showModalBottomSheet<void>(
  context: context,
  isScrollControlled: true,
  useSafeArea: true,
  constraints: const BoxConstraints(maxWidth: 600),
  builder: (_) => const _EditProfileSheet(),
);

class _EditProfileSheet extends StatefulWidget {
  const _EditProfileSheet();
  @override
  State<_EditProfileSheet> createState() => _EditProfileSheetState();
}

class _EditProfileSheetState extends State<_EditProfileSheet> {
  final _form = GlobalKey<FormState>();
  late final TextEditingController _name;
  late final TextEditingController _landmark;
  late AreaPath _location;
  bool _saving = false;
  @override
  void initState() {
    super.initState();
    final p = context.read<AppController>().profile!;
    _name = TextEditingController(text: p.name);
    _landmark = TextEditingController(text: p.landmark);
    _location = p.location;
  }

  @override
  void dispose() {
    _name.dispose();
    _landmark.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    return SingleChildScrollView(
      padding: EdgeInsets.fromLTRB(
        24,
        0,
        24,
        MediaQuery.viewInsetsOf(context).bottom + 24,
      ),
      child: Form(
        key: _form,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              c.text('अपने बारे में थोड़ा बताएँ', 'A little about you'),
              style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w800),
            ),
            const SizedBox(height: 22),
            TextFormField(
              controller: _name,
              enabled: !_saving,
              maxLength: 100,
              decoration: InputDecoration(labelText: c.text('नाम', 'Name')),
              validator: (s) => (s?.trim().length ?? 0) < 2
                  ? c.text('कम से कम 2 अक्षर लिखें।', 'At least 2 characters.')
                  : null,
            ),
            const SizedBox(height: 12),
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: const Icon(Icons.home_outlined, color: MCColors.green),
              title: Text(
                '${_location.shortLabel} · Ward ${_location.ward}',
                style: const TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w800,
                ),
              ),
              subtitle: Text(
                _location.fullLabel,
                style: const TextStyle(color: MCColors.muted, fontSize: 10),
              ),
              trailing: const Icon(Icons.keyboard_arrow_down),
              onTap: _saving
                  ? null
                  : () async {
                      final area = await pickArea(context, initial: _location);
                      if (area != null && mounted) {
                        setState(() => _location = area);
                      }
                    },
            ),
            const SizedBox(height: 14),
            TextFormField(
              controller: _landmark,
              enabled: !_saving,
              maxLength: 150,
              decoration: InputDecoration(
                labelText: c.text(
                  'पास की पहचान (वैकल्पिक)',
                  'Nearby landmark (optional)',
                ),
              ),
            ),
            const SizedBox(height: 20),
            SizedBox(
              width: double.infinity,
              child: FilledButton(
                onPressed: _saving
                    ? null
                    : () async {
                        if (!_form.currentState!.validate()) return;
                        setState(() => _saving = true);
                        try {
                          await c.saveProfile(
                            _name.text,
                            _location,
                            _landmark.text,
                          );
                          if (context.mounted) Navigator.pop(context);
                        } catch (e) {
                          if (context.mounted) {
                            notifyUser(context, AppController.friendlyError(e));
                          }
                        } finally {
                          if (mounted) setState(() => _saving = false);
                        }
                      },
                child: Text(
                  _saving
                      ? c.text('सेव कर रहे हैं…', 'Saving…')
                      : c.text('बदलाव सेव करें', 'Save changes'),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
