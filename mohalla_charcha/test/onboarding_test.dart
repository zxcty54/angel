import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:intl/date_symbol_data_local.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:mohalla_charcha/controllers/app_controller.dart';
import 'package:mohalla_charcha/main.dart';
import 'package:mohalla_charcha/repositories/demo_repository.dart';
import 'package:mohalla_charcha/services/onboarding_service.dart';
import 'package:mohalla_charcha/ui/app_shell.dart';
import 'package:mohalla_charcha/ui/screens/welcome_screen.dart';

Future<(AppController, SharedPreferences)> launchFirst(
  WidgetTester tester, {
  Size size = const Size(390, 844),
  bool completed = false,
  double textScale = 1,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  tester.platformDispatcher.textScaleFactorTestValue = textScale;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
  SharedPreferences.setMockInitialValues({
    if (completed) OnboardingService.completionKey: true,
  });
  final prefs = await SharedPreferences.getInstance();
  final c = AppController(
    DemoRepository(delay: Duration.zero, preferences: prefs),
    preferences: prefs,
  );
  await tester.runAsync(c.initialize);
  addTearDown(c.dispose);
  await tester.pumpWidget(
    ChangeNotifierProvider.value(value: c, child: const MohallaApp()),
  );
  await tester.pumpAndSettle();
  return (c, prefs);
}

void main() {
  setUpAll(() => initializeDateFormatting('hi'));

  test(
    'fresh install shows welcome; existing demo data does not bypass it',
    () async {
      SharedPreferences.setMockInitialValues({'mohalla.demo.v1': '{}'});
      final prefs = await SharedPreferences.getInstance();
      expect(OnboardingService(prefs).isComplete, isFalse);
    },
  );

  test(
    'completion persists across service reconstruction and is idempotent',
    () async {
      SharedPreferences.setMockInitialValues({});
      final prefs = await SharedPreferences.getInstance();
      final service = OnboardingService(prefs);
      await service.complete();
      await service.complete();
      expect(service.isComplete, isTrue);
      expect(OnboardingService(prefs).isComplete, isTrue);
      expect(prefs.getBool(OnboardingService.completionKey), isTrue);
    },
  );

  test(
    'without device preferences completion is still session-local',
    () async {
      final service = OnboardingService(null);
      await service.complete();
      expect(service.isComplete, isTrue);
      expect(OnboardingService(null).isComplete, isFalse);
    },
  );

  for (final size in [
    const Size(320, 720),
    const Size(390, 844),
    const Size(800, 600),
    const Size(1440, 900),
  ]) {
    testWidgets('first-launch welcome renders before feed at $size', (
      tester,
    ) async {
      await launchFirst(tester, size: size);
      expect(find.byType(WelcomeScreen), findsOneWidget);
      expect(find.byType(AppShell), findsNothing);
      expect(find.byKey(const Key('welcome_title_0')), findsOneWidget);
      expect(find.byKey(const Key('welcome_next')), findsOneWidget);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('all three steps, back, language and persistent completion', (
    tester,
  ) async {
    final (c, prefs) = await launchFirst(tester);
    await tester.tap(find.byKey(const Key('welcome_language')));
    await tester.pumpAndSettle();
    expect(find.text('Your mohalla.\nYour voice.'), findsOneWidget);
    await tester.tap(find.byKey(const Key('welcome_next')));
    await tester.pumpAndSettle();
    expect(
      find.text('District → Block → Gram Panchayat → Ward'),
      findsOneWidget,
    );
    await tester.tap(find.byKey(const Key('welcome_next')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('welcome_title_2')), findsOneWidget);
    await tester.tap(find.byKey(const Key('welcome_back')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('welcome_title_1')), findsOneWidget);
    await tester.tap(find.byKey(const Key('welcome_next')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('welcome_finish')));
    await tester.pumpAndSettle();
    expect(c.hasCompletedWelcome, isTrue);
    expect(prefs.getBool(OnboardingService.completionKey), isTrue);
    expect(find.byType(WelcomeScreen), findsNothing);
    expect(find.byType(AppShell), findsOneWidget);
    expect(prefs.getBool('mohalla.hindi'), isFalse);
    expect(tester.takeException(), isNull);
  });

  testWidgets('skip completes welcome without changing the demo profile', (
    tester,
  ) async {
    final (c, prefs) = await launchFirst(tester);
    final profile = c.profile!;
    await tester.tap(find.byKey(const Key('welcome_skip')));
    await tester.pumpAndSettle();
    expect(c.profile!.id, profile.id);
    expect(c.profile!.location.identity, profile.location.identity);
    expect(prefs.getBool(OnboardingService.completionKey), isTrue);
    expect(find.byType(AppShell), findsOneWidget);
  });

  testWidgets('returning launch bypasses the tour', (tester) async {
    await launchFirst(tester, completed: true);
    expect(find.byType(WelcomeScreen), findsNothing);
    expect(find.byType(AppShell), findsOneWidget);
  });

  testWidgets(
    'profile can replay and close the tour without clearing completion',
    (tester) async {
      final (c, prefs) = await launchFirst(tester, completed: true);
      c.setTab(3);
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byKey(const Key('replay_welcome')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('replay_welcome')));
      await tester.pumpAndSettle();
      expect(find.byType(WelcomeScreen), findsOneWidget);
      await tester.tap(find.byKey(const Key('welcome_next')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('welcome_next')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('welcome_finish')));
      await tester.pumpAndSettle();
      expect(find.byType(WelcomeScreen), findsNothing);
      expect(c.hasCompletedWelcome, isTrue);
      expect(prefs.getBool(OnboardingService.completionKey), isTrue);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('welcome exposes complete rural hierarchy picker', (
    tester,
  ) async {
    await launchFirst(tester);
    await tester.tap(find.byKey(const Key('welcome_next')));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('welcome_choose_ward')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('welcome_choose_ward')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('ग्रामीण'));
    await tester.pumpAndSettle();
    expect(find.text('ग्राम पंचायत'), findsOneWidget);
    expect(find.text('प्रखंड / Block'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('large text at narrow width keeps navigation accessible', (
    tester,
  ) async {
    await launchFirst(tester, size: const Size(320, 720), textScale: 1.5);
    await tester.tap(find.byKey(const Key('welcome_next')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('welcome_next')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('welcome_finish')), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
