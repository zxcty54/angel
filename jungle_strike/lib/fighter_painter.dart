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
  required double idleSeconds,
  required bool startled,
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
  final baseY = footY + bob + (weapon == 'ROCKET' && !prone ? 3*scale : 0);
  final rifleColor = weapon == 'ROCKET' ? const Color(0xffba6844) : weapon == 'PISTOL' ? const Color(0xff62777d) : weapon == 'SPREAD' ? const Color(0xff538b9c) : const Color(0xff52686e);

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
  // The pistol is a one-hand ready stance; long guns visibly use a two-hand grip.
  if (weapon == 'PISTOL') {
    block(20,-58,20,8,skinShade); block(24,-58,16,4,skinLight); block(32,-54,8,8,ink);
  } else {
    block(-8,-56,24,8,skinShade); block(-4,-56,20,4,skinLight); block(20,-56,16,8,skinShade); block(24,-56,12,4,skinLight);
    block(0,-52,12,8,ink); block(28,-52,12,8,ink);
  }

  // Face, visible eye, brow, nose, hair and bandana.
  block(-4,-92,28,28,ink); block(0,-88,20,24,skinShade); block(4,-88,16,20,skin); block(12,-84,8,4,skinLight);
  if (startled) {
    block(12,-84,12,8,const Color(0xfff6edd4)); block(16,-84,4,8,ink);
    block(20,-76,4,4,skinShade); block(8,-88,12,4,ink);
  } else {
    block(16,-80,4,4,ink); block(20,-76,4,4,skinShade); block(12,-76,8,4,ink);
    if (firing) { block(12,-72,8,4,const Color(0xfffff0d8)); }
  }
  block(-4,-96,28,12,ink); block(0,-92,24,8,armor); block(4,-88,16,4,armorHi);
  block(-8,-88,8,16,ink); block(-4,-76,4,8,armorMid);
  final scarfWave = math.sin(frame * .48) * 4;
  block(-20,-88+scarfWave,16,4,const Color(0xffe85e4f));
  block(-28,-84+math.sin(frame*.48+1)*6,12,4,const Color(0xffff9a5b));

  // Gun pose changes with weight: compact one-hand pistol, braced rifle, heavy launcher.
  final rifleY = idleSeconds >= 5 ? -52.0 : weapon == 'ROCKET' ? -57.0 : -60.0;
  if (weapon == 'PISTOL') {
    block(28,rifleY-4,32,12,ink);
    block(32,rifleY,24,4,rifleColor);
    block(52,rifleY,16,4,armorHi);
    block(36,rifleY+4,8,8,ink);
    block(24,rifleY-4,8,8,skinLight);
    block(36,rifleY-8,8,4,ink);
  } else {
    final length = weapon == 'ROCKET' ? 88.0 : 72.0;
    block(8,rifleY-4,length,16,ink);
    block(12,rifleY,length-12,8,rifleColor);
    block(16,rifleY-4,28,4,armorHi); block(20,rifleY+8,12,8,ink);
    block(60,rifleY+4,16,4,armorHi); block(76,rifleY+4,16,4,ink); block(88,rifleY+4,8,4,armorHi);
    block(36,rifleY-8,8,4,ink); block(40,rifleY-4,4,4,gold);
    block(8,rifleY+4,12,8,ink); block(12,rifleY+4,8,4,skin);
    block(48,rifleY+4,12,8,ink); block(52,rifleY+4,8,4,skinLight);
    if (weapon == 'ROCKET') { block(32,rifleY-8,40,4,gold); block(20,rifleY+12,12,4,ink); block(72,rifleY,20,8,Color.lerp(rifleColor,ink,.4)!); }
    if (weapon == 'SPREAD') { block(80,rifleY,16,4,armorHi); }
  }
  if (idleSeconds >= 5) {
    final cleanWave = math.sin(frame * .18).abs();
    block(46,rifleY+12+cleanWave*3,12,8,const Color(0xff72d9d0));
    block(42,rifleY+8,8,4,skinLight);
  }
  if (firing) {
    final muzzleX = weapon == 'PISTOL' ? 68.0 : weapon == 'ROCKET' ? 104.0 : 96.0;
    final flash = Path()
      ..moveTo((x+muzzleX*scale),baseY-58*scale)
      ..lineTo((x+(muzzleX+12)*scale),baseY-66*scale)
      ..lineTo((x+(muzzleX+8)*scale),baseY-58*scale)
      ..lineTo((x+(muzzleX+16)*scale),baseY-54*scale)
      ..lineTo((x+(muzzleX+4)*scale),baseY-52*scale)
      ..close();
    canvas.drawPath(flash,Paint()..color=gold);
  }
}
