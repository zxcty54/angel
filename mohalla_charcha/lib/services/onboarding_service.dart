import 'package:shared_preferences/shared_preferences.dart';

/// First-launch tour state is device-local, not an account/profile field.
/// A fresh install/cleared app data shows the tour again. Logout, demo reset,
/// profile edits and replaying the tour do not clear this preference.
class OnboardingService {
  OnboardingService(this.preferences)
    : _complete = preferences?.getBool(completionKey) ?? false;

  static const completionKey = 'mohalla.welcome.v1.complete';
  final SharedPreferences? preferences;
  bool _complete;

  bool get isComplete => _complete;

  Future<void> complete() async {
    if (_complete) return;
    final saved = await preferences?.setBool(completionKey, true) ?? true;
    if (!saved) {
      throw StateError('Could not save welcome preference. Please try again.');
    }
    // Only leave the tour after persistence succeeds.
    _complete = true;
  }
}
