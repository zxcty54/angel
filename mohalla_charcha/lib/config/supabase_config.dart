/// SUPABASE YAHAN CONFIGURE KARNA HAI.
///
/// Default = demo; no account, OTP or internet required.
/// Recommended: keep credentials outside source and pass --dart-define.
/// Only the PUBLIC anon/publishable key belongs in a mobile application.
/// NEVER put a service_role key, Telegram token or signing password here.
///
/// flutter run --dart-define=USE_SUPABASE=true \
///   --dart-define=SUPABASE_URL=https://YOUR_PROJECT.supabase.co \
///   --dart-define=SUPABASE_ANON_KEY=YOUR_PUBLIC_KEY
///
/// GitHub: Repository Variables SUPABASE_URL and SUPABASE_ANON_KEY.
/// See docs/SUPABASE_SETUP.md for SQL, SMS provider and private storage setup.
abstract final class SupabaseConfig {
  static const enabled = bool.fromEnvironment(
    'USE_SUPABASE',
    defaultValue: false,
  );

  // If you prefer editing a file, change defaultValue below (PUBLIC values only).
  static const url = String.fromEnvironment('SUPABASE_URL', defaultValue: '');
  static const anonKey = String.fromEnvironment(
    'SUPABASE_ANON_KEY',
    defaultValue: '',
  );

  static void validate() {
    if (!enabled) return;
    final uri = Uri.tryParse(url);
    if (uri == null ||
        uri.scheme != 'https' ||
        uri.host.isEmpty ||
        anonKey.isEmpty) {
      throw StateError(
        'Supabase enabled but URL/public key are missing. '
        'Set lib/config/supabase_config.dart or use --dart-define.',
      );
    }
  }
}
