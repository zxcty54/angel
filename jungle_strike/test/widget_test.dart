import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:jungle_strike/main.dart';

void main() {
  testWidgets('shows the standalone game and touch controls', (tester) async {
    SharedPreferences.setMockInitialValues({});
    await tester.pumpWidget(const JungleStrikeApp());
    expect(find.text('JUNGLE STRIKE'), findsOneWidget);
    expect(find.text('PLAY STORY CAMPAIGN'), findsOneWidget);
    await tester.tap(find.text('PLAY STORY CAMPAIGN'));
    await tester.pumpAndSettle();
    expect(find.text('FIRE'), findsOneWidget);
    expect(find.byIcon(Icons.control_camera), findsOneWidget);
    expect(find.byIcon(Icons.gps_fixed), findsOneWidget);
    expect(find.textContaining('ARMOR'), findsOneWidget);
    expect(find.textContaining('Tap to deploy'), findsOneWidget);
  });
}
