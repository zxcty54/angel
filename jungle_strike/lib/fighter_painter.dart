import 'dart:math' as math;
import 'dart:ui';
import 'package:flutter/material.dart';

/// Draws Asha as a grounded, muscular side-view fighter with a readable face,
/// exposed arms and a weapon visibly held in both hands.
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
  final bob = math.sin(frame * .28) * (prone ? 0 : 1.4 * scale);
  final fx = x;
  final fy = footY + bob;
  const outline = Color(0xff111b25);
  const armor = Color(0xff263946);
  const armorLight = Color(0xff54707a);
  const skin = Color(0xffc9845e);
  final edge = Paint()..color = outline;
  final skinPaint = Paint()..shader = const LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [Color(0xfff0b18a), skin, Color(0xff8b513e)]).createShader(Rect.fromLTWH(fx-36*scale, fy-84*scale, 80*scale, 75*scale));
  final armorPaint = Paint()..shader = const LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [Color(0xff55727b), armor, Color(0xff172832)]).createShader(Rect.fromLTWH(fx-32*scale, fy-75*scale, 68*scale, 80*scale));
  final riflePaint = Paint()..shader = const LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: [Color(0xff8ca4a2), Color(0xff34444c), Color(0xff111b22)]).createShader(Rect.fromLTWH(fx, fy-65*scale, 76*scale, 20*scale));

  canvas.save();
  if (dodging) {
    canvas.translate(fx, fy);
    canvas.rotate(-.12);
    canvas.translate(-fx, -fy);
  }
  canvas.drawOval(Rect.fromCenter(center: Offset(fx, fy+2*scale), width: 54*scale, height: 10*scale), Paint()..color = (dodging ? const Color(0x9972ffe3) : const Color(0x7738e0cb))..maskFilter = MaskFilter.blur(BlurStyle.normal, dodging ? 15*scale : 6*scale));

  if (prone) {
    // Low crawl pose: face and both hands remain behind the raised rifle.
    canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(fx-23*scale, fy-26*scale, 48*scale, 17*scale), Radius.circular(7*scale)), armorPaint);
    canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(fx-23*scale, fy-26*scale, 48*scale, 17*scale), Radius.circular(7*scale)), Paint()..style=PaintingStyle.stroke..strokeWidth=1.6*scale..color=outline);
    canvas.drawOval(Rect.fromLTWH(fx-15*scale, fy-12*scale, 20*scale, 8*scale), Paint()..color=const Color(0xff202d35));
    canvas.drawCircle(Offset(fx+25*scale, fy-22*scale), 11*scale, skinPaint);
    canvas.drawPath(Path()..moveTo(fx+16*scale,fy-29*scale)..quadraticBezierTo(fx+26*scale,fy-41*scale,fx+37*scale,fy-30*scale)..lineTo(fx+34*scale,fy-26*scale)..lineTo(fx+18*scale,fy-25*scale)..close(), edge);
    canvas.drawCircle(Offset(fx+30*scale,fy-23*scale), 1.3*scale, edge);
    _drawRifle(canvas, fx+10*scale, fy-37*scale, scale, weapon, riflePaint, outline);
    canvas.restore();
    return;
  }

  // Boots and articulated tactical trousers.
  final legPaint = Paint()..shader = const LinearGradient(colors: [Color(0xff44515a), Color(0xff18232d)]).createShader(Rect.fromLTWH(fx-22*scale,fy-34*scale,42*scale,35*scale));
  canvas.drawPath(Path()..moveTo(fx-14*scale,fy-35*scale)..lineTo(fx+13*scale,fy-35*scale)..lineTo(fx+12*scale,fy-13*scale)..lineTo(fx+17*scale,fy-5*scale)..lineTo(fx+5*scale,fy-3*scale)..lineTo(fx-1*scale,fy-21*scale)..lineTo(fx-12*scale,fy-9*scale)..lineTo(fx-17*scale,fy-5*scale)..lineTo(fx-23*scale,fy-9*scale)..close(), legPaint);
  canvas.drawCircle(Offset(fx+8*scale,fy-17*scale),5.2*scale,Paint()..color=const Color(0xff65717a));
  canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(fx+4*scale,fy-10*scale,14*scale,8*scale),Radius.circular(3*scale)),edge);
  canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(fx-27*scale,fy-10*scale,15*scale,8*scale),Radius.circular(3*scale)),edge);
  canvas.drawRect(Rect.fromLTWH(fx-22*scale,fy-34*scale,29*scale,5*scale),Paint()..color=const Color(0xff111a21));

  // Broad torso, tactical plate, shoulder pads and prominent bare biceps.
  final torso = Path()..moveTo(fx-16*scale,fy-69*scale)..quadraticBezierTo(fx,fy-77*scale,fx+17*scale,fy-68*scale)..lineTo(fx+20*scale,fy-38*scale)..quadraticBezierTo(fx,fy-30*scale,fx-18*scale,fy-38*scale)..close();
  canvas.drawPath(torso,armorPaint);
  canvas.drawPath(torso,Paint()..style=PaintingStyle.stroke..strokeWidth=1.7*scale..color=outline);
  canvas.drawOval(Rect.fromLTWH(fx-27*scale,fy-67*scale,21*scale,21*scale),skinPaint);
  canvas.drawOval(Rect.fromLTWH(fx+10*scale,fy-67*scale,22*scale,21*scale),skinPaint);
  canvas.drawOval(Rect.fromLTWH(fx-24*scale,fy-63*scale,15*scale,9*scale),Paint()..color=const Color(0x66ffd0aa));
  canvas.drawOval(Rect.fromLTWH(fx+15*scale,fy-63*scale,15*scale,9*scale),Paint()..color=const Color(0x66ffd0aa));
  canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(fx-12*scale,fy-68*scale,26*scale,30*scale),Radius.circular(5*scale)),Paint()..color=armorLight);
  canvas.drawLine(Offset(fx,fy-65*scale),Offset(fx,fy-41*scale),Paint()..color=const Color(0xff9aafb2)..strokeWidth=1.4*scale);
  canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(fx-18*scale,fy-39*scale,38*scale,6*scale),Radius.circular(2*scale)),Paint()..color=const Color(0xffcf9e48));
  canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(fx-3*scale,fy-39*scale,9*scale,6*scale),Radius.circular(1*scale)),edge);

  // Strong forearms angle forward to the trigger and front grip.
  final armPaint = Paint()..color=skin;
  canvas.drawLine(Offset(fx+23*scale,fy-58*scale),Offset(fx+35*scale,fy-51*scale),Paint()..color=outline..strokeWidth=12*scale..strokeCap=StrokeCap.round);
  canvas.drawLine(Offset(fx+23*scale,fy-58*scale),Offset(fx+35*scale,fy-51*scale),Paint()..color=const Color(0xffd89a72)..strokeWidth=8.5*scale..strokeCap=StrokeCap.round);
  canvas.drawLine(Offset(fx-20*scale,fy-55*scale),Offset(fx+3*scale,fy-49*scale),Paint()..color=outline..strokeWidth=11*scale..strokeCap=StrokeCap.round);
  canvas.drawLine(Offset(fx-20*scale,fy-55*scale),Offset(fx+3*scale,fy-49*scale),Paint()..color=const Color(0xffca8963)..strokeWidth=7.5*scale..strokeCap=StrokeCap.round);
  canvas.drawCircle(Offset(fx+35*scale,fy-51*scale),5*scale,armPaint);
  canvas.drawCircle(Offset(fx+3*scale,fy-49*scale),5*scale,armPaint);

  // Expressive visible face, brow, eye, nose, hair and a modern headset.
  canvas.drawOval(Rect.fromLTWH(fx-5*scale,fy-91*scale,27*scale,31*scale),skinPaint);
  canvas.drawPath(Path()..moveTo(fx-7*scale,fy-77*scale)..quadraticBezierTo(fx-10*scale,fy-94*scale,fx+4*scale,fy-97*scale)..quadraticBezierTo(fx+25*scale,fy-94*scale,fx+24*scale,fy-80*scale)..lineTo(fx+17*scale,fy-84*scale)..lineTo(fx+3*scale,fy-82*scale)..lineTo(fx-4*scale,fy-74*scale)..close(),Paint()..color=const Color(0xff16232c));
  canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(fx+8*scale,fy-81*scale,9*scale,2*scale),Radius.circular(scale)),Paint()..color=const Color(0xff171d24));
  canvas.drawCircle(Offset(fx+13*scale,fy-77*scale),1.7*scale,Paint()..color=const Color(0xfff7eee0));
  canvas.drawLine(Offset(fx+19*scale,fy-70*scale),Offset(fx+24*scale,fy-69*scale),Paint()..color=const Color(0xff704234)..strokeWidth=1.2*scale);
  canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(fx-8*scale,fy-83*scale,5*scale,10*scale),Radius.circular(2*scale)),Paint()..color=const Color(0xff55d9ca));

  _drawRifle(canvas, fx+8*scale, fy-58*scale, scale, weapon, riflePaint, outline);
  if (firing) {
    final muzzle = Offset(fx+78*scale,fy-55*scale);
    canvas.drawCircle(muzzle,weapon=='ROCKET'?12*scale:7*scale,Paint()..color=const Color(0xffffa44f)..maskFilter=MaskFilter.blur(BlurStyle.normal,8*scale));
    final flare = Path();
    final flareRadius = weapon == 'ROCKET' ? 15*scale : 9*scale;
    for (var i = 0; i < 10; i++) {
      final angle = -math.pi / 2 + i * math.pi / 5;
      final radius = i.isEven ? flareRadius : flareRadius * .42;
      final point = Offset(muzzle.dx + math.cos(angle) * radius, muzzle.dy + math.sin(angle) * radius);
      if (i == 0) { flare.moveTo(point.dx, point.dy); } else { flare.lineTo(point.dx, point.dy); }
    }
    flare.close();
    canvas.drawPath(flare, Paint()..color=const Color(0xfffff1b0));
  }
  canvas.restore();
}

void _drawRifle(Canvas canvas, double x, double y, double s, String weapon, Paint body, Color outline) {
  final height = weapon == 'ROCKET' ? 11*s : 7*s;
  final total = weapon == 'ROCKET' ? 68*s : 60*s;
  final box = Rect.fromLTWH(x,y,total,height);
  canvas.drawRRect(RRect.fromRectAndRadius(box,Radius.circular(2*s)),Paint()..color=outline);
  canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(x+5*s,y+1*s,total-12*s,height-2*s),Radius.circular(2*s)),body);
  canvas.drawRect(Rect.fromLTWH(x+total-8*s,y+height*.32,weapon=='ROCKET'?21*s:16*s,2.5*s),Paint()..color=const Color(0xffd9e6df));
  canvas.drawRect(Rect.fromLTWH(x+12*s,y+height,8*s,5*s),Paint()..color=const Color(0xff252f36));
  canvas.drawLine(Offset(x+24*s,y-2*s),Offset(x+24*s,y+height+2*s),Paint()..color=const Color(0xff71898a)..strokeWidth=1.5*s);
  canvas.drawCircle(Offset(x+8*s,y+height/2),4*s,Paint()..color=const Color(0xff202c34));
  // Gloves sit over the receiver, making the two-handed grip unmistakable.
  canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(x+4*s,y-2*s,10*s,7*s),Radius.circular(3*s)),Paint()..color=const Color(0xff151e24));
  canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(x+31*s,y+height-1*s,11*s,7*s),Radius.circular(3*s)),Paint()..color=const Color(0xff151e24));
}
