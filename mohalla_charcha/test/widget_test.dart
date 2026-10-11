import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:intl/date_symbol_data_local.dart';
import 'package:provider/provider.dart';
import 'package:mohalla_charcha/controllers/app_controller.dart';
import 'package:mohalla_charcha/main.dart';
import 'package:mohalla_charcha/repositories/demo_repository.dart';

Future<AppController> launch(WidgetTester tester, Size size) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  final c = AppController(DemoRepository(delay: Duration.zero));
  await tester.runAsync(c.initialize);
  await c
      .completeWelcome(); // These existing tests exercise the returning-user feed.
  addTearDown(c.dispose);
  await tester.pumpWidget(
    ChangeNotifierProvider.value(value: c, child: const MohallaApp()),
  );
  await tester.pumpAndSettle();
  return c;
}

Finder get verticalScroll => find
    .byWidgetPredicate(
      (w) => w is Scrollable && w.axisDirection == AxisDirection.down,
    )
    .first;

void main() {
  setUpAll(() => initializeDateFormatting('hi'));
  for (final size in [
    const Size(320, 720),
    const Size(390, 844),
    const Size(800, 600),
    const Size(1440, 900),
  ]) {
    testWidgets('adaptive feed renders without overflow at $size', (
      tester,
    ) async {
      await launch(tester, size);
      expect(find.text('पड़ोस की बात, पड़ोस के साथ।'), findsOneWidget);
      expect(find.text('DEMO · नमूना डेटा'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });
  }
  testWidgets('language toggle and mobile tabs work', (tester) async {
    await launch(tester, const Size(390, 844));
    await tester.tap(find.text('EN'));
    await tester.pumpAndSettle();
    expect(
      find.text('Good neighbours.\nGreat neighbourhoods.'),
      findsOneWidget,
    );
    await tester.tap(find.text('Map'));
    await tester.pumpAndSettle();
    expect(find.text('Your neighbourhood, mapped'), findsOneWidget);
    await tester.tap(find.text('Together'));
    await tester.pumpAndSettle();
    expect(find.text('Small acts. Real community.'), findsOneWidget);
    await tester.tap(find.text('You'));
    await tester.pumpAndSettle();
    expect(find.text('You belong here.'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
  testWidgets('location picker exposes complete urban/rural branch', (
    tester,
  ) async {
    await launch(tester, const Size(390, 844));
    await tester.tap(find.text('कंकड़बाग · Ward 22'));
    await tester.pumpAndSettle();
    expect(find.text('अपना इलाका चुनें'), findsOneWidget);
    await tester.tap(find.text('ग्रामीण'));
    await tester.pumpAndSettle();
    expect(find.text('ग्राम पंचायत'), findsOneWidget);
    expect(find.text('प्रखंड / Block'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
  testWidgets(
    'publish navigates to detail, not discard confirmation; add a reply',
    (tester) async {
      final c = await launch(tester, const Size(390, 844));
      await tester.tap(find.byType(FloatingActionButton));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byType(TextFormField).at(0),
        'A brand new local conversation',
      );
      await tester.enterText(
        find.byType(TextFormField).at(1),
        'Let us get together and exchange our favourite books.',
      );
      await tester.scrollUntilVisible(
        find.text('मोहल्ले में साझा करें'),
        350,
        scrollable: verticalScroll,
      );
      await tester.tap(find.text('मोहल्ले में साझा करें'));
      await tester.pumpAndSettle();
      expect(find.text('मोहल्ले की बातचीत'), findsOneWidget);
      expect(find.text('अधूरी पोस्ट छोड़ें?'), findsNothing);
      expect(c.posts.first.title, 'A brand new local conversation');
      await tester.scrollUntilVisible(
        find.byType(TextField),
        400,
        scrollable: verticalScroll,
      );
      await tester.enterText(find.byType(TextField), 'I can bring two books!');
      await tester.pump();
      await tester.ensureVisible(find.text('भेजें'));
      await tester.pump();
      await tester.tap(find.text('भेजें'));
      await tester.pumpAndSettle();
      expect(find.text('I can bring two books!'), findsOneWidget);
      expect(c.posts.first.commentCount, 1);
      expect(tester.takeException(), isNull);
    },
  );
}
