import 'dart:math' as math;
import 'package:flutter/material.dart';

/// Original, high-detail pixel-art side-view fighter sprite.
void paintFighter(
  Canvas canvas, {
  required double x,
  required double footY,
  required double scale,
  required int frame,
  required bool prone,
  required bool dodging,
  required bool firing,
  required String weapon,
}) {
  const ink = Color(0xff101920);
  const skin = Color(0xffd69069);
  const skinLight = Color(0xffffbc8d);
  const skinShade = Color(0xff874f43);
  const armor = Color(0xff263c47);
  const armorMid = Color(0xff3f6470);
  const armorHi = Color(0xff79a3a2);
  const pants = Color(0xff293744);
  const gold = Color(0xffffc857);
  const tile = 4.0;
  final px = tile * scale;
  final bob = prone ? 0.0 : math.sin(frame * .28) * 1.5 * scale;
  final baseY = footY + bob;
  final rifleColor = weapon == 'ROCKET' ? const Color(0xffba6844) : weapon == 'SPREAD' ? const Color(0xff538b9c) : const Color(0xff52686e);

  void block(double left, double top, double width, double height, Color color) {
    final l = ((x + left * scale) / px).roundToDouble() * px;
    final t = ((baseY + top * scale) / px).roundToDouble() * px;
    canvas.drawRect(Rect.fromLTWH(l, t, (width / tile).round() * px, (height / tile).round() * px), Paint()..color = color);
  }

  canvas.drawRect(Rect.fromLTWH(x - 24*scale, footY + 2*scale, 60*scale, 6*scale), Paint()..color = (dodging ? const Color(0xff50e4d1) : const Color(0x8843d0b2))..maskFilter = MaskFilter.blur(BlurStyle.normal, dodging ? 12*scale : 5*scale));

  if (prone) {
    // Low pixel crawl silhouette with face, exposed forearm and rifle still readable.
    block(-24,-28,48,20,ink); block(-20,-28,40,16,armor); block(-16,-24,28,4,armorHi); block(-12,-20,20,4,armorMid);
    block(20,-32,20,16,skinShade); block(20,-32,16,12,skin); block(28,-32,8,4,ink); block(32,-24,4,4,ink);
    block(28,-40,48,8,ink); block(32,-36,44,4,rifleColor); block(52,-44,8,8,ink); block(60,-36,24,4,armorHi);
    block(26,-36,12,8,skin); block(44,-32,12,8,skinLight); block(-20,-8,20,8,pants); block(-24,-4,16,4,ink);
    if (firing) block(80,-40,12,8,gold);
    return;
  }

  // Boots, split tactical trousers, knee pads, belt and vest: all crisp pixel clusters.
  block(-24,-12,20,8,ink); block(-20,-16,16,8,armorMid); block(4,-12,20,8,ink); block(8,-16,16,8,armorMid);
  block(-16,-36,12,24,ink); block(-12,-36,12,20,pants); block(-16,-28,8,8,armorMid); block(-12,-24,8,4,armorHi);
  block(4,-36,12,24,ink); block(8,-36,12,20,pants); block(8,-28,8,8,armorMid); block(12,-24,8,4,armorHi);
  block(-20,-40,40,8,ink); block(-16,-40,32,4,gold); block(-12,-68,36,32,ink);
  block(-8,-68,28,28,armor); block(-4,-64,24,20,armorMid); block(0,-60,4,20,armorHi);
  block(-8,-44,28,4,armorHi); block(0,-44,8,4,gold); block(-4,-56,8,4,ink); block(8,-56,8,4,ink);

  // Large exposed upper arms/biceps with highlight and shadow pixels.
  block(-28,-68,20,20,ink); block(-24,-64,16,16,skinShade); block(-20,-64,12,12,skin);
  block(-20,-64,8,4,skinLight); block(-12,-56,8,8,skinShade);
  block(16,-68,20,20,ink); block(20,-64,16,16,skinShade); block(20,-64,12,12,skin);
  block(24,-64,8,4,skinLight); block(20,-52,12,4,skinShade);
  // Tactical gloves and forearms angle inward to grip the gun.
  block(-8,-56,24,8,skinShade); block(-4,-56,20,4,skinLight); block(20,-56,16,8,skinShade); block(24,-56,12,4,skinLight);
  block(0,-52,12,8,ink); block(28,-52,12,8,ink);

  // Face, visible eye, brow, nose, hair and bandana.
  block(-4,-92,28,28,ink); block(0,-88,20,24,skinShade); block(4,-88,16,20,skin); block(12,-84,8,4,skinLight);
  block(16,-80,4,4,ink); block(20,-76,4,4,skinShade); block(12,-76,8,4,ink);
  block(-4,-96,28,12,ink); block(0,-92,24,8,armor); block(4,-88,16,4,armorHi);
  block(-8,-88,8,16,ink); block(-4,-76,4,8,armorMid);

  // Modern rifle, visibly held by both hands, distinct silhouette per weapon.
  final rifleY = -60.0;
  block(8,rifleY-4,72,16,ink);
  block(12,rifleY,64,8,rifleColor);
  block(16,rifleY-4,28,4,armorHi); block(20,rifleY+8,12,8,ink);
  block(60,rifleY+4,16,4,armorHi); block(76,rifleY+4,16,4,ink); block(88,rifleY+4,8,4,armorHi);
  block(36,rifleY-8,8,4,ink); block(40,rifleY-4,4,4,gold);
  block(8,rifleY+4,12,8,ink); block(12,rifleY+4,8,4,skin);
  block(48,rifleY+4,12,8,ink); block(52,rifleY+4,8,4,skinLight);
  if (weapon == 'ROCKET') { block(32,rifleY-8,32,4,gold); block(20,rifleY+12,12,4,ink); }
  if (weapon == 'SPREAD') { block(80,rifleY,16,4,armorHi); }
  if (firing) {
    final flash = Path()
      ..moveTo((x+96*scale),baseY-58*scale)
      ..lineTo((x+108*scale),baseY-66*scale)
      ..lineTo((x+104*scale),baseY-58*scale)
      ..lineTo((x+112*scale),baseY-54*scale)
      ..lineTo((x+100*scale),baseY-52*scale)
      ..close();
    canvas.drawPath(flash,Paint()..color=gold);
  }
}
