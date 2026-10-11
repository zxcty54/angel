import 'package:flutter/material.dart';

abstract final class MCColors {
  static const background = Color(0xFFF6F7F3);
  static const surface = Colors.white;
  static const ink = Color(0xFF263D35);
  static const muted = Color(0xFF78867E);
  static const primary = Color(0xFFBD5337);
  static const primarySoft = Color(0xFFFBEDE6);
  static const green = Color(0xFF39765D);
  static const greenSoft = Color(0xFFEAF3EC);
  static const amber = Color(0xFFB7832E);
  static const amberSoft = Color(0xFFFCF3DF);
  static const blue = Color(0xFF577F94);
  static const blueSoft = Color(0xFFEDF4F7);
  static const border = Color(0xFFE6EBE4);
}

ThemeData buildAppTheme() {
  final scheme = ColorScheme.fromSeed(
    seedColor: MCColors.primary,
    primary: MCColors.primary,
    secondary: MCColors.green,
    surface: MCColors.surface,
    onSurface: MCColors.ink,
  );
  final base = ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    fontFamily: 'Manrope',
    fontFamilyFallback: const ['NotoSansDevanagari'],
    scaffoldBackgroundColor: MCColors.background,
    visualDensity: VisualDensity.standard,
  );
  return base.copyWith(
    textTheme: base.textTheme.apply(
      bodyColor: MCColors.ink,
      displayColor: MCColors.ink,
    ),
    appBarTheme: const AppBarTheme(
      backgroundColor: MCColors.surface,
      foregroundColor: MCColors.ink,
      elevation: 0,
      scrolledUnderElevation: 0,
      centerTitle: false,
    ),
    dividerTheme: const DividerThemeData(
      color: MCColors.border,
      thickness: 1,
      space: 1,
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: MCColors.background,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 15),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: const BorderSide(color: MCColors.border),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: const BorderSide(color: MCColors.border),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: const BorderSide(color: MCColors.primary, width: 1.5),
      ),
      hintStyle: const TextStyle(color: MCColors.muted, fontSize: 13),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: MCColors.primary,
        foregroundColor: Colors.white,
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
        textStyle: const TextStyle(
          fontSize: 14,
          fontWeight: FontWeight.w700,
          fontFamily: 'Manrope',
          fontFamilyFallback: ['NotoSansDevanagari'],
        ),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: MCColors.ink,
        side: const BorderSide(color: MCColors.border),
        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      ),
    ),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      backgroundColor: MCColors.ink,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: MCColors.surface,
      indicatorColor: MCColors.primarySoft,
      height: 74,
      labelTextStyle: WidgetStateProperty.resolveWith(
        (s) => TextStyle(
          fontSize: 11,
          fontWeight: s.contains(WidgetState.selected)
              ? FontWeight.w800
              : FontWeight.w500,
          color: s.contains(WidgetState.selected)
              ? MCColors.primary
              : MCColors.muted,
        ),
      ),
    ),
    floatingActionButtonTheme: const FloatingActionButtonThemeData(
      backgroundColor: MCColors.primary,
      foregroundColor: Colors.white,
      elevation: 2,
    ),
    bottomSheetTheme: const BottomSheetThemeData(
      backgroundColor: MCColors.surface,
      showDragHandle: true,
      modalBarrierColor: Color(0x66303A33),
    ),
  );
}
