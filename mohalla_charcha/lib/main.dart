import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/date_symbol_data_local.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'config/supabase_config.dart';
import 'controllers/app_controller.dart';
import 'repositories/community_repository.dart';
import 'repositories/demo_repository.dart';
import 'repositories/supabase_repository.dart';
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
                  'Mohalla Charcha setup error\n\n${AppController.friendlyError(e)}\n\n'
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
      title: 'Mohalla Charcha',
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
                'Mohalla Charcha',
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
    if (!c.hasSession) return const PhoneLoginScreen();
    if (c.profile == null) return const ProfileOnboardingScreen();
    return const AppShell();
  }
}
