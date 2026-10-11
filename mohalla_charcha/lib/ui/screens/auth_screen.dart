import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import '../../controllers/app_controller.dart';
import '../../models/location.dart';
import '../../services/phone_auth_service.dart';
import '../../theme/app_theme.dart';
import '../widgets/common.dart';
import '../widgets/location_picker.dart';

class PhoneLoginScreen extends StatefulWidget {
  const PhoneLoginScreen({super.key});
  @override
  State<PhoneLoginScreen> createState() => _PhoneLoginScreenState();
}

class _PhoneLoginScreenState extends State<PhoneLoginScreen> {
  final _phone = TextEditingController();
  final _otp = TextEditingController();
  late final PhoneAuthService _auth;
  bool _sent = false;
  bool _busy = false;
  int _seconds = 0;
  Timer? _timer;
  @override
  void initState() {
    super.initState();
    _auth = PhoneAuthService(Supabase.instance.client);
  }

  @override
  void dispose() {
    _timer?.cancel();
    _phone.dispose();
    _otp.dispose();
    super.dispose();
  }

  Future<void> _send() async {
    if (_busy || _seconds > 0) return;
    setState(() => _busy = true);
    try {
      await _auth.sendOtp(_phone.text);
      if (!mounted) return;
      setState(() {
        _sent = true;
        _seconds = 60;
      });
      _timer?.cancel();
      _timer = Timer.periodic(const Duration(seconds: 1), (timer) {
        if (!mounted || _seconds <= 1) {
          timer.cancel();
          if (mounted) setState(() => _seconds = 0);
        } else {
          setState(() => _seconds--);
        }
      });
    } catch (e) {
      if (mounted) notifyUser(context, AppController.friendlyError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _verify() async {
    setState(() => _busy = true);
    try {
      await _auth.verify(_phone.text, _otp.text);
      if (mounted) await context.read<AppController>().reloadSession();
    } catch (e) {
      if (mounted) notifyUser(context, AppController.friendlyError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 460),
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(28),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const BrandMark(size: 52),
                      const SizedBox(width: 14),
                      const Text(
                        'Mohalla\nCharcha',
                        style: TextStyle(
                          fontSize: 22,
                          height: 1.2,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 34),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(20),
                    child: Image.asset(
                      'assets/images/neighborhood.jpg',
                      height: 160,
                      fit: BoxFit.cover,
                    ),
                  ),
                  const SizedBox(height: 26),
                  Text(
                    c.text(
                      'अपना मोहल्ला,\nअपनी आवाज़।',
                      'Your neighbourhood.\nYour voice.',
                    ),
                    style: const TextStyle(
                      fontSize: 31,
                      height: 1.4,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text(
                    c.text(
                      'अपने मोबाइल नंबर से जुड़ें। आपका नंबर पड़ोसियों को नहीं दिखेगा।',
                      'Join with your phone. Your number is never shown to neighbours.',
                    ),
                    style: const TextStyle(
                      color: MCColors.muted,
                      fontSize: 13,
                      height: 1.8,
                    ),
                  ),
                  const SizedBox(height: 25),
                  TextField(
                    controller: _phone,
                    enabled: !_sent && !_busy,
                    keyboardType: TextInputType.phone,
                    inputFormatters: [
                      FilteringTextInputFormatter.digitsOnly,
                      LengthLimitingTextInputFormatter(10),
                    ],
                    autofillHints: const [
                      AutofillHints.telephoneNumberNational,
                    ],
                    decoration: InputDecoration(
                      labelText: c.text('मोबाइल नंबर', 'Mobile number'),
                      prefixText: '+91  ',
                    ),
                  ),
                  if (_sent) ...[
                    const SizedBox(height: 18),
                    TextField(
                      controller: _otp,
                      enabled: !_busy,
                      keyboardType: TextInputType.number,
                      inputFormatters: [
                        FilteringTextInputFormatter.digitsOnly,
                        LengthLimitingTextInputFormatter(6),
                      ],
                      autofillHints: const [AutofillHints.oneTimeCode],
                      decoration: InputDecoration(
                        labelText: c.text('6 अंक का OTP', '6-digit OTP'),
                      ),
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        TextButton(
                          onPressed: _busy
                              ? null
                              : () {
                                  _timer?.cancel();
                                  setState(() {
                                    _sent = false;
                                    _seconds = 0;
                                    _otp.clear();
                                  });
                                },
                          child: Text(c.text('नंबर बदलें', 'Change number')),
                        ),
                        const Spacer(),
                        TextButton(
                          onPressed: _busy || _seconds > 0 ? null : _send,
                          child: Text(
                            _seconds > 0
                                ? '${_seconds}s'
                                : c.text('OTP फिर भेजें', 'Resend OTP'),
                          ),
                        ),
                      ],
                    ),
                  ],
                  const SizedBox(height: 22),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton(
                      onPressed: _busy
                          ? null
                          : _sent
                          ? _verify
                          : _send,
                      child: Text(
                        _busy
                            ? c.text('थोड़ा रुकें…', 'One moment…')
                            : _sent
                            ? c.text('सत्यापित करें', 'Verify & continue')
                            : c.text('OTP भेजें', 'Send OTP'),
                      ),
                    ),
                  ),
                  const SizedBox(height: 18),
                  Text(
                    c.text(
                      'यह केवल पड़ोसियों का नेटवर्क है। सरकारी विभागों को टिकट नहीं भेजे जाते। SMS आपके Supabase provider से जाएगा।',
                      'A people-to-people network. No tickets go to government departments. SMS is sent by your configured Supabase provider.',
                    ),
                    style: const TextStyle(
                      fontSize: 10,
                      color: MCColors.muted,
                      height: 1.8,
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextButton(
                    onPressed: c.toggleLanguage,
                    child: Text(
                      c.isHindi
                          ? 'Continue in English'
                          : 'हिन्दी में जारी रखें',
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

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
                  'फोन सत्यापन पूरा हुआ। अब अपने इलाके का समुदाय चुनें।',
                  'Your phone is verified. Now choose the community you call home.',
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
