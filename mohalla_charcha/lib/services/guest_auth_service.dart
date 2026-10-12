import 'package:supabase_flutter/supabase_flutter.dart';

/// Bihar Local login: NO phone number, NO OTP, NO password.
///
/// One launch = one Supabase anonymous guest session bound to this device's
/// app install. supabase_flutter persists and refreshes the session from
/// local storage, so neighbours stay signed in until they sign out or the
/// app's data is cleared. Enable "Anonymous sign-ins" in the Supabase
/// Dashboard (Authentication > Providers) before launch.
class GuestAuthService {
  GuestAuthService(this.client);

  final SupabaseClient client;

  bool get hasSession => client.auth.currentSession != null;

  /// Restores the stored guest session, or silently creates a new one for a
  /// first-time user. Returns true when an authenticated session exists.
  Future<bool> ensureSession() async {
    if (client.auth.currentSession != null) return true;
    final res = await client.auth.signInAnonymously();
    return res.session != null;
  }
}
