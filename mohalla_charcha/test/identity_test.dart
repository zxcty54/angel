import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mohalla_charcha/config/app_identity.dart';
import 'package:mohalla_charcha/services/onboarding_service.dart';
import 'package:mohalla_charcha/ui/widgets/common.dart';

void main() {
  test(
    'approved display name fits store limit; first-launch key stays stable',
    () {
      expect(AppIdentity.displayName, 'Bihar Local - Mohalla Charcha');
      expect(AppIdentity.displayName.length, 29);
      expect(OnboardingService.completionKey, 'mohalla.welcome.v1.complete');
    },
  );
  for (final scale in [1.0, 1.5]) {
    testWidgets('new wordmark fits a narrow header at text scale $scale', (
      tester,
    ) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: MediaQuery(
              data: MediaQueryData(textScaler: TextScaler.linear(scale)),
              child: const SizedBox(
                width: 118,
                height: 90,
                child: BrandWordmark(),
              ),
            ),
          ),
        ),
      );
      expect(find.text(AppIdentity.primaryName), findsOneWidget);
      expect(find.text(AppIdentity.secondaryName), findsOneWidget);
      expect(tester.takeException(), isNull);
    });
  }
}
