import 'package:supabase_flutter/supabase_flutter.dart';

/// Supabase Auth + your configured SMS provider. No fake OTP in demo mode.
/// India: configure DLT templates/headers with your provider before launch.
class PhoneAuthService {
  PhoneAuthService(this.client);
  final SupabaseClient client;
  String normalize(String input) {
    final digits = input.replaceAll(RegExp(r'[^0-9]'), '');
    final local = digits.length == 12 && digits.startsWith('91')
        ? digits.substring(2)
        : digits;
    if (!RegExp(r'^[6-9][0-9]{9}$').hasMatch(local)) {
      throw ArgumentError('Enter a valid 10-digit Indian mobile number.');
    }
    return '+91$local';
  }

  Future<void> sendOtp(String input) =>
      client.auth.signInWithOtp(phone: normalize(input));
  Future<void> verify(String input, String code) async {
    if (!RegExp(r'^[0-9]{6}$').hasMatch(code.trim())) {
      throw ArgumentError('Enter the 6-digit OTP.');
    }
    await client.auth.verifyOTP(
      phone: normalize(input),
      token: code.trim(),
      type: OtpType.sms,
    );
  }
}
