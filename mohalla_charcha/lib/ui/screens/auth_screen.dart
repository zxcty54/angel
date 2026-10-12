import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../controllers/app_controller.dart';
import '../../models/location.dart';
import '../../theme/app_theme.dart';
import '../widgets/common.dart';
import '../widgets/location_picker.dart';

class ProfileOnboardingScreen extends StatefulWidget {
  const ProfileOnboardingScreen({super.key});
  @override
  State<ProfileOnboardingScreen> createState() =>
      _ProfileOnboardingScreenState();
}

class _ProfileOnboardingScreenState extends State<ProfileOnboardingScreen> {
  final _name = TextEditingController();
  AreaPath? _location;
  bool _saving = false;
  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    return Scaffold(
      appBar: AppBar(
        title: Text(c.text('अपने पड़ोस से जुड़ें', 'Make yourself at home')),
      ),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 460),
          child: ListView(
            padding: const EdgeInsets.all(28),
            children: [
              const BrandMark(size: 58),
              const SizedBox(height: 26),
              Text(
                c.text('आपका नाम और आपका वार्ड', 'A name and a neighbourhood'),
                style: const TextStyle(
                  fontSize: 27,
                  fontWeight: FontWeight.w800,
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 12),
              Text(
                c.text(
                  'गेस्ट खाता तैयार है — किसी नंबर या OTP की ज़रूरत नहीं। अब अपने इलाके का समुदाय चुनें।',
                  'Guest account ready — no number or OTP needed. Now choose the community you call home.',
                ),
                style: const TextStyle(
                  color: MCColors.muted,
                  fontSize: 13,
                  height: 1.8,
                ),
              ),
              const SizedBox(height: 25),
              TextField(
                controller: _name,
                enabled: !_saving,
                maxLength: 100,
                decoration: InputDecoration(
                  labelText: c.text('आपका नाम', 'Your name'),
                ),
              ),
              const SizedBox(height: 14),
              OutlinedButton.icon(
                onPressed: _saving
                    ? null
                    : () async {
                        final area = await pickArea(
                          context,
                          initial: _location,
                        );
                        if (mounted && area != null) {
                          setState(() => _location = area);
                        }
                      },
                icon: const Icon(Icons.location_on_outlined),
                label: Text(
                  _location == null
                      ? c.text('अपना वार्ड चुनें', 'Choose your home ward')
                      : '${_location!.shortLabel} · Ward ${_location!.ward}',
                ),
              ),
              const SizedBox(height: 24),
              FilledButton(
                onPressed: _saving || _location == null
                    ? null
                    : () async {
                        if (_name.text.trim().length < 2) {
                          notifyUser(
                            context,
                            c.text(
                              'कम से कम 2 अक्षर का नाम लिखें।',
                              'Please enter at least 2 characters for your name.',
                            ),
                          );
                          return;
                        }
                        setState(() => _saving = true);
                        try {
                          await c.saveProfile(_name.text, _location!, '');
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
                      : c.text('मेरा मोहल्ला खोलें', 'Enter my neighbourhood'),
                ),
              ),
              const SizedBox(height: 18),
              Text(
                c.text(
                  'निवास का प्रमाण नहीं लिया जाता। सुरक्षित रहें और निजी जानकारी न साझा करें।',
                  'No proof of residence is collected. Stay safe and do not share private details.',
                ),
                style: const TextStyle(
                  color: MCColors.muted,
                  fontSize: 11,
                  height: 1.7,
                ),
              ),
              TextButton(
                onPressed: () => safeAction(context, c.signOut),
                child: Text(c.text('लॉग आउट', 'Sign out')),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
