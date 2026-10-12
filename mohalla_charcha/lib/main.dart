import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/date_symbol_data_local.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'config/supabase_config.dart';
import 'config/app_identity.dart';
import 'controllers/app_controller.dart';
import 'repositories/community_repository.dart';
import 'repositories/demo_repository.dart';
import 'repositories/supabase_repository.dart';
import 'services/guest_auth_service.dart';
import 'theme/app_theme.dart';
import 'ui/app_shell.dart';
import 'ui/screens/auth_screen.dart';
import 'ui/screens/welcome_screen.dart';
import 'ui/widgets/common.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await initializeDateFormatting('hi');
  try {
    SupabaseConfig.validate();
    final prefs = await SharedPreferences.getInstance();
    final CommunityRepository repository;
    if (SupabaseConfig.enabled) {
      await Supabase.initialize(
        url: SupabaseConfig.url,
        publishableKey: SupabaseConfig.anonKey,
      );
      // No-OTP guest login: restores the device session or silently
      // creates a new anonymous one before any profile/feed call.
      await GuestAuthService(Supabase.instance.client).ensureSession();
      repository = SupabaseRepository(Supabase.instance.client);
    } else {
      repository = DemoRepository(preferences: prefs);
    }
    final controller = AppController(repository, preferences: prefs);
    runApp(
      ChangeNotifierProvider.value(
        value: controller,
        child: const MohallaApp(),
      ),
    );
    unawaited(controller.initialize());
  } catch (e) {
    runApp(
      MaterialApp(
        debugShowCheckedModeBanner: false,
        theme: buildAppTheme(),
        home: Scaffold(
          body: Center(
            child: Padding(
              padding: const EdgeInsets.all(28),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 560),
                child: Text(
                  '${AppIdentity.displayName} setup error\n\n${AppController.friendlyError(e)}\n\n'
                  'See lib/config/supabase_config.dart and docs/SUPABASE_SETUP.md.\n'
                  'Use USE_SUPABASE=false for the working local demo.',
                  style: const TextStyle(fontSize: 15, height: 1.8),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class MohallaApp extends StatelessWidget {
  const MohallaApp({super.key});
  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    return MaterialApp(
      title: AppIdentity.displayName,
      debugShowCheckedModeBanner: false,
      theme: buildAppTheme(),
      locale: Locale(c.isHindi ? 'hi' : 'en'),
      supportedLocales: const [Locale('hi'), Locale('en')],
      localizationsDelegates: const [
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      home: const _AuthGate(),
    );
  }
}

class _AuthGate extends StatelessWidget {
  const _AuthGate();
  @override
  Widget build(BuildContext context) {
    final c = context.watch<AppController>();
    // First Flutter screen on a fresh install, before feed/auth.
    if (!c.hasCompletedWelcome) return const WelcomeScreen();
    if (!c.initialized || (c.loading && c.selectedLocation == null)) {
      return const Scaffold(
        body: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              BrandMark(size: 64),
              SizedBox(height: 22),
              Text(
                AppIdentity.displayName,
                style: TextStyle(fontSize: 22, fontWeight: FontWeight.w800),
              ),
              SizedBox(height: 20),
              SizedBox(
                width: 24,
                height: 24,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            ],
          ),
        ),
      );
    }
    if (c.error != null && c.selectedLocation == null) {
      return Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 540),
              child: EmptyState(
                title: c.text(
                  'समुदाय खोल नहीं पाए',
                  'Could not open the community',
                ),
                message: c.error!,
                icon: Icons.wifi_off,
                action: c.reloadSession,
                actionLabel: c.text('फिर कोशिश करें', 'Retry'),
              ),
            ),
          ),
        ),
      );
    }
    // Startup normally guarantees an anonymous guest session already; this
    // branch only appears if the guest sign-in itself failed.
    if (!c.hasSession) return const _GuestSessionRetry();
    if (c.profile == null) return const ProfileOnboardingScreen();
    return const AppShell();
  }
}

/// Shown only when the anonymous guest session could not be established.
class _GuestSessionRetry extends StatefulWidget {
  const _GuestSessionRetry();
  @override
  State<_GuestSessionRetry> createState() => _GuestSessionRetryState();
}

class _GuestSessionRetryState extends State<_GuestSessionRetry> {
  bool _busy = false;
  Future<void> _join() async {
    setState(() => _busy = true);
    try {
      final ok = await GuestAuthService(
        Supabase.instance.client,
      ).ensureSession();
      if (ok && mounted) await context.read<AppController>().reloadSession();
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
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const BrandMark(size: 56),
                const SizedBox(height: 22),
                Text(
                  c.text(
                    'मेहमान सत्र शुरू नहीं हुआ',
                    'Guest session did not start',
                  ),
                  style: const TextStyle(
                    fontSize: 19,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                const SizedBox(height: 10),
                Text(
                  c.text(
                    'किसी नंबर या OTP की ज़रूरत नहीं है। कनेक्शन जाँचकर दोबारा कोशिश करें।',
                    'No number or OTP is needed. Check your connection and try again.',
                  ),
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: Colors.black54, height: 1.7),
                ),
                const SizedBox(height: 20),
                FilledButton(
                  onPressed: _busy ? null : _join,
                  child: Text(
                    _busy
                        ? c.text('थोड़ा रुकें…', 'One moment…')
                        : c.text('फिर जुड़ें', 'Join again'),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
