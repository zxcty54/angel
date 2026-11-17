import 'dart:async';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() => runApp(const JungleStrikeApp());

class JungleStrikeApp extends StatelessWidget {
  const JungleStrikeApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Jungle Strike', debugShowCheckedModeBanner: false,
    theme: ThemeData.dark().copyWith(scaffoldBackgroundColor: const Color(0xff101a25), colorScheme: const ColorScheme.dark(primary: Color(0xffffc857))),
    home: const GameMenu(),
  );
}

class GameMenu extends StatelessWidget {
  const GameMenu({super.key});

  @override
  Widget build(BuildContext context) => Scaffold(
    body: Stack(fit: StackFit.expand, children: [
      Image.asset('assets/jungle_frontier.png', fit: BoxFit.cover),
      Container(color: const Color(0xaa07131b)),
      SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 560),
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Icon(Icons.bolt_rounded, color: Color(0xffffc857), size: 64),
                  const Text('JUNGLE STRIKE', textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 32, fontWeight: FontWeight.w900, letterSpacing: 3)),
                  const SizedBox(height: 8),
                  const Text('THE LAST LIGHT', textAlign: TextAlign.center,
                    style: TextStyle(color: Color(0xff76e1c4), letterSpacing: 4, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 26),
                  Container(
                    padding: const EdgeInsets.all(18),
                    decoration: BoxDecoration(color: const Color(0xdd101a25), borderRadius: BorderRadius.circular(18), border: Border.all(color: Colors.white24)),
                    child: const Text(
                      'When the Iron Vulture occupied the valley, Captain Asha’s younger brother went missing in the evacuation. Asha returns with an old rescue beacon and one promise: no one gets left behind. Find the survivors, take back the relay towers, and face the warlord before dawn.',
                      style: TextStyle(height: 1.65, color: Colors.white70),
                    ),
                  ),
                  const SizedBox(height: 18),
                  FilledButton.icon(
                    onPressed: () => Navigator.push<void>(context, MaterialPageRoute(builder: (_) => const GameScreen())),
                    icon: const Icon(Icons.person), label: const Text('PLAY STORY CAMPAIGN'),
                    style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(54)),
                  ),
                  const SizedBox(height: 12),
                  const Text('Single-player · Offline · No account or server needed', textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 12, color: Colors.white60)),
                ],
              ),
            ),
          ),
        ),
      ),
    ]),
  );
}

String missionBackground(int level)=>switch(level){2=>'assets/mission_bridge.png',4=>'assets/mission_village.png',6=>'assets/mission_fortress.png',_=>'assets/jungle_frontier.png'};

class GameScreen extends StatefulWidget { const GameScreen({super.key}); @override State<GameScreen> createState()=>_GameScreenState(); }
class _GameScreenState extends State<GameScreen> {
  Timer? timer;
  double x = .16, jump = 0, scroll = 0;
  int score = 0, armor = 3, level = 1, bossHp = 10, killsThisMission = 0;
  int unlockedMission = 1, bestScore = 0;
  bool running = false, firing = false, hitThisWave = false;
  bool campaignWon = false, prone = false, dodging = false, dodgeReady = true;
  String weapon = 'PULSE', emote = '';
  static const _weapons = ['PULSE', 'SPREAD', 'ROCKET'];
  static const _emotes = ['💪', '🔥', '😎', '❤️'];

  @override
  void initState() {
    super.initState();
    _restoreProgress();
  }

  Future<void> _restoreProgress() async {
    final prefs = await SharedPreferences.getInstance();
    if (!mounted) return;
    setState(() {
      unlockedMission = (prefs.getInt('unlocked_mission') ?? 1).clamp(1, 6).toInt();
      bestScore = prefs.getInt('best_score') ?? 0;
    });
  }

  Future<void> _saveProgress() async {
    final prefs = await SharedPreferences.getInstance();
    final latestBest = math.max(bestScore, score).toInt();
    await prefs.setInt('unlocked_mission', unlockedMission);
    await prefs.setInt('best_score', latestBest);
    if (mounted && latestBest != bestScore) setState(() => bestScore = latestBest);
  }

  void start() {
    setState(() {
      running = true;
      campaignWon = false;
      score = 0;
      armor = 3;
      x = .16;
      scroll = 0;
      hitThisWave = false;
      killsThisMission = 0;
      level = unlockedMission;
      bossHp = 10;
      prone = false;
      dodging = false;
      weapon = 'PULSE';
      emote = '';
    });
    timer?.cancel();
    timer = Timer.periodic(const Duration(milliseconds: 55), (_) {
      if (!mounted || !running) return;
      var save = false;
      setState(() {
        scroll += .012;
        score += firing ? (weapon == 'ROCKET' ? 3 : 2) : 1;
        final enemy = .88 - scroll * 1.15;
        if (!hitThisWave && (enemy - x).abs() < .08) {
          hitThisWave = true;
          if (firing) {
            final damage = weapon == 'ROCKET' ? 4 : weapon == 'SPREAD' ? 2 : 1;
            score += weapon == 'ROCKET' ? 180 : 120;
            if (level == 6) {
              bossHp -= damage;
              if (bossHp <= 0) {
                running = false;
                campaignWon = true;
                unlockedMission = 6;
                save = true;
              }
            } else {
              killsThisMission++;
              if (killsThisMission >= 3) {
                level++;
                unlockedMission = math.max(unlockedMission, level).toInt();
                killsThisMission = 0;
                bossHp = 10;
                save = true;
              }
            }
          } else if (jump == 0 && !dodging && !prone) {
            armor--;
            if (armor <= 0) running = false;
          }
        }
        if (scroll > 1) {
          scroll = 0;
          hitThisWave = false;
        }
        if (!running || campaignWon || (score > bestScore && score % 100 == 0)) save = true;
      });
      if (save) _saveProgress();
    });
  }

  void move(double delta) => setState(() => x = (x + delta).clamp(.05, .66).toDouble());

  void doJump() {
    if (!running) return;
    setState(() { jump = 1; prone = false; });
    Future.delayed(const Duration(milliseconds: 650), () {
      if (mounted) setState(() => jump = 0);
    });
  }

  void doDodge() {
    if (!running || !dodgeReady) return;
    setState(() { dodging = true; dodgeReady = false; prone = false; x = (x + .10).clamp(.05, .66).toDouble(); });
    Future.delayed(const Duration(milliseconds: 430), () { if (mounted) setState(() => dodging = false); });
    Future.delayed(const Duration(milliseconds: 1200), () { if (mounted) setState(() => dodgeReady = true); });
  }

  void cycleWeapon() => setState(() {
    weapon = _weapons[(_weapons.indexOf(weapon) + 1) % _weapons.length];
  });

  void nextEmote() => setState(() {
    emote = _emotes[(_emotes.indexOf(emote) + 1) % _emotes.length];
    Future.delayed(const Duration(milliseconds: 1300), () { if (mounted) setState(() => emote = ''); });
  });

  @override
  void dispose() { timer?.cancel(); super.dispose(); }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(
      title: const Text('JUNGLE STRIKE', style: TextStyle(fontWeight: FontWeight.w900, letterSpacing: 1.3)),
      backgroundColor: const Color(0xff101a25),
      actions: [IconButton(icon: const Icon(Icons.help_outline), onPressed: () => showDialog<void>(
        context: context,
        builder: (c) => const AlertDialog(title: Text('How to play'), content: Text('Move, jump, hold DOWN to go prone, or dodge to evade. Cycle PULSE, SPREAD and ROCKET weapons. Tap the emote button to cheer! Progress saves at mission checkpoints.'),
      ))],
    ),
    body: SafeArea(child: Column(children: [
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        child: Row(children: [
          Text('SCORE ${score.toString().padLeft(4, '0')}', style: const TextStyle(color: Color(0xffffd166), fontWeight: FontWeight.w900, fontSize: 12)),
          const SizedBox(width: 10),
          Text('STAGE $level/6', style: const TextStyle(color: Color(0xff76e1c4), fontWeight: FontWeight.w800, fontSize: 12)),
          const Spacer(),
          const Text('ARMOR ', style: TextStyle(color: Colors.white70, fontWeight: FontWeight.bold, fontSize: 11)),
          ...List.generate(3, (i) => Icon(Icons.favorite, size: 16, color: i < armor ? const Color(0xffff5a62) : Colors.white24)),
        ]),
      ),
      if (level == 6 && running) Padding(
        padding: const EdgeInsets.symmetric(horizontal: 18),
        child: ClipRRect(borderRadius: BorderRadius.circular(8), child: LinearProgressIndicator(value: (bossHp / 10).clamp(0, 1).toDouble(), minHeight: 8, color: const Color(0xffef554b), backgroundColor: Colors.white24)),
      ),
      Expanded(child: GestureDetector(
        onTap: running ? null : start,
        child: Stack(fit: StackFit.expand, children: [
          Image.asset(missionBackground(level), fit: BoxFit.cover, errorBuilder: (c, e, s) => const DecoratedBox(decoration: BoxDecoration(gradient: LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: [Color(0xff14283a), Color(0xff385c55), Color(0xff182b30)])))),
          CustomPaint(size: Size.infinite, painter: JunglePainter(x: x, jump: jump, scroll: scroll, shooting: firing, level: level, weapon: weapon, prone: prone, dodging: dodging)),
          if (emote.isNotEmpty && running) Positioned(left: MediaQuery.sizeOf(context).width * x, top: 30, child: Text(emote, style: const TextStyle(fontSize: 40))),
          if (!running) Center(child: Container(
            margin: const EdgeInsets.all(18), padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(color: const Color(0xdd101a25), borderRadius: BorderRadius.circular(22), border: Border.all(color: const Color(0xffffd166))),
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              Icon(campaignWon ? Icons.emoji_events : armor == 0 ? Icons.replay : Icons.sports_esports, color: const Color(0xffffd166), size: 50),
              const SizedBox(height: 10),
              Text(campaignWon ? 'VALLEY IS FREE' : armor == 0 ? 'MISSION FAILED' : level == 6 ? 'IRON VULTURE · FINAL BOSS' : 'MISSION $level · ${const ['THE EVACUATION', 'BROKEN BRIDGE', 'RELAY TOWER', 'ASHEN VILLAGE', 'STORM PASS', 'IRON VULTURE'][level - 1]}', textAlign: TextAlign.center, style: const TextStyle(color: Colors.white, fontSize: 17, fontWeight: FontWeight.w900, letterSpacing: 1)),
              const SizedBox(height: 8),
              Text(campaignWon ? 'Asha found the beacon. Her brother answered. The valley came home.  SCORE $score' : armor == 0 ? 'Checkpoint saved at Stage $unlockedMission · Best $bestScore' : 'Tap to deploy · Resume from Stage $unlockedMission', textAlign: TextAlign.center, style: const TextStyle(color: Colors.white70, height: 1.5)),
            ]),
          )),
        ]),
      )),
      Container(
        color: const Color(0xff172432), padding: const EdgeInsets.fromLTRB(12, 9, 12, 14),
        child: Column(children: [
          Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            Row(children: [control(Icons.chevron_left, () => move(-.06)), const SizedBox(width: 5), control(Icons.chevron_right, () => move(.06))]),
            Row(children: [control(Icons.arrow_upward_rounded, doJump), const SizedBox(width: 5), control(Icons.directions_run, () => doDodge(), tint: const Color(0xff42b9a5)), const SizedBox(width: 5), control(Icons.keyboard_arrow_down, () => setState(() => prone = !prone), tint: const Color(0xff7485ca))]),
            GestureDetector(onLongPressStart: (_) => setState(() => firing = true), onLongPressEnd: (_) => setState(() => firing = false), onTapDown: (_) => setState(() => firing = true), onTapUp: (_) => setState(() => firing = false), child: Container(padding: const EdgeInsets.symmetric(horizontal: 17, vertical: 15), decoration: BoxDecoration(color: const Color(0xffef554b), borderRadius: BorderRadius.circular(16)), child: const Row(children: [Icon(Icons.bolt, color: Colors.white), SizedBox(width: 4), Text('FIRE', style: TextStyle(color: Colors.white, fontWeight: FontWeight.w900))]))),
          ]),
          const SizedBox(height: 7),
          Row(mainAxisAlignment: MainAxisAlignment.center, children: [
            OutlinedButton.icon(onPressed: cycleWeapon, icon: const Icon(Icons.auto_awesome, size: 16), label: Text(weapon), style: OutlinedButton.styleFrom(foregroundColor: const Color(0xffffd166), visualDensity: VisualDensity.compact)),
            const SizedBox(width: 10),
            OutlinedButton.icon(onPressed: nextEmote, icon: const Icon(Icons.emoji_emotions_outlined, size: 16), label: Text(emote.isEmpty ? 'EMOTE' : 'AGAIN'), style: OutlinedButton.styleFrom(foregroundColor: const Color(0xff76e1c4), visualDensity: VisualDensity.compact)),
            if (prone) const Padding(padding: EdgeInsets.only(left: 8), child: Text('PRONE', style: TextStyle(color: Colors.white60, fontSize: 10))),
            if (!dodgeReady) const Padding(padding: EdgeInsets.only(left: 8), child: Text('DODGE…', style: TextStyle(color: Colors.white60, fontSize: 10))),
          ]),
        ]),
      ),
    ])),
  );

  Widget control(IconData icon, VoidCallback action, {Color tint = Colors.white}) => InkWell(
    onTap: action, borderRadius: BorderRadius.circular(15),
    child: Container(width: 45, height: 48, decoration: BoxDecoration(color: const Color(0xff293b4b), borderRadius: BorderRadius.circular(15), border: Border.all(color: Colors.white12)), child: Icon(icon, color: tint, size: 27)),
  );
}

class JunglePainter extends CustomPainter {
  JunglePainter({required this.x, required this.jump, required this.scroll, required this.shooting, required this.level, required this.weapon, required this.prone, required this.dodging});
  final double x, jump, scroll; final bool shooting, prone, dodging; final int level; final String weapon;
  @override
  void paint(Canvas c, Size s) {
    final ground = s.height * .78;
    // Atmospheric overlay, foreground jungle silhouettes and a glowing track.
    c.drawRect(Offset.zero & s, Paint()..shader = LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: [const Color(0x00101a25), const Color(0x3320312a), const Color(0xff14221f)]).createShader(Offset.zero & s));
    final haze = Paint()..color = const Color(0x446ae0c1)..maskFilter = const MaskFilter.blur(BlurStyle.normal, 40);
    c.drawCircle(Offset(s.width*.76, s.height*.42), s.width*.22, haze);
    for (int i=0;i<10;i++) {
      final xx=((i*83.0-scroll*185)%(s.width+100))-45; final h=75.0+(i%4)*25;
      final path=Path()..moveTo(xx,ground+6)..lineTo(xx+8,ground-h)..lineTo(xx-26,ground-h+18)..lineTo(xx+10,ground-h+11)..lineTo(xx+38,ground-h+29)..lineTo(xx+11,ground-h+20)..lineTo(xx+18,ground+6)..close();
      c.drawPath(path,Paint()..color=Color.lerp(const Color(0xff143b35),const Color(0xff245147),(i%3)*.18)!);
    }
    c.drawRect(Rect.fromLTWH(0,ground,s.width,s.height-ground),Paint()..shader=const LinearGradient(colors:[Color(0xff344737),Color(0xff14221e)]).createShader(Rect.fromLTWH(0,ground,s.width,s.height-ground)));
    for(int i=0;i<18;i++){final xx=((i*67.0-scroll*340)%(s.width+60))-25;final yy=ground+10+(i%4)*13;c.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(xx,yy,25+(i%3)*12,3),const Radius.circular(3)),Paint()..color=const Color(0xff83936b));}
    final px=s.width*x, py=ground-30-jump*65;
    final heroGlow=Paint()..color=(dodging?const Color(0xff65e8d0):const Color(0x88a5f3d0))..maskFilter=MaskFilter.blur(BlurStyle.normal,dodging?18:8);
    c.drawOval(Rect.fromCenter(center:Offset(px,ground+3),width:dodging?64:46,height:9),heroGlow);
    if(prone){
      c.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(px-20,ground-25,34,12),const Radius.circular(6)),Paint()..color=const Color(0xff36b8aa));
      c.drawCircle(Offset(px+17,ground-20),7,Paint()..color=const Color(0xffdf795c));
      c.drawRect(Rect.fromLTWH(px+2,ground-17,29,4),Paint()..color=const Color(0xffd8e6df));
    }else{
      c.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(px-12,py-37,22,15),const Radius.circular(5)),Paint()..color=const Color(0xffdf795c));
      c.drawRect(Rect.fromLTWH(px+4,py-32,2,3),Paint()..color=Colors.white);
      c.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(px-11,py-23,22,22),const Radius.circular(5)),Paint()..color=const Color(0xff36b8aa));
      c.drawRect(Rect.fromLTWH(px-9,py-4,7,15),Paint()..color=const Color(0xffffc857)); c.drawRect(Rect.fromLTWH(px+2,py-4,7,15),Paint()..color=const Color(0xffffc857));
      c.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(px+6,py-20,28,6),const Radius.circular(3)),Paint()..color=const Color(0xffd8e6df));
    }

    final dx=s.width*(.88-scroll*1.15);
    if(dx>px+28){final center=Offset(dx,ground-(level==6?86:72));final size=level==6?62.0:32.0;c.drawCircle(center,size*.72,Paint()..color=const Color(0x66ff634e)..maskFilter=MaskFilter.blur(BlurStyle.normal,level==6?25:14));c.drawRRect(RRect.fromRectAndRadius(Rect.fromCenter(center:center,width:size,height:level==6?38:19),Radius.circular(level==6?14:8)),Paint()..shader=const LinearGradient(colors:[Color(0xfff4774e),Color(0xff8b2d46)]).createShader(Rect.fromCenter(center:center,width:size,height:40)));c.drawCircle(Offset(dx+size*.18,center.dy-2),level==6?5:3,Paint()..color=const Color(0xffffe9a4));c.drawRect(Rect.fromLTWH(dx-size*.28,center.dy+10,level==6?9:5,level==6?22:11),Paint()..color=const Color(0xff323a40));if(level==6){c.drawLine(Offset(dx-size*.65,center.dy-10),Offset(dx+size*.65,center.dy-10),Paint()..color=const Color(0xffffc857)..strokeWidth=4);}}
    if(shooting){final beamColor=weapon=='ROCKET'?const Color(0xffff7043):weapon=='SPREAD'?const Color(0xff77eaff):const Color(0xffffe680);final beam=Paint()..color=beamColor..strokeWidth=(weapon=='ROCKET'?6.0:weapon=='SPREAD'?4.0:3.0)..maskFilter=const MaskFilter.blur(BlurStyle.normal,2);final startY=prone?ground-20:py-17;c.drawLine(Offset(px+25,startY),Offset(math.max(px+48,dx-15).toDouble(),ground-72),beam);if(weapon=='ROCKET')c.drawCircle(Offset(px+42,startY),7,Paint()..color=const Color(0xffffa35b)..maskFilter=const MaskFilter.blur(BlurStyle.normal,7));if(weapon=='SPREAD'){c.drawLine(Offset(px+25,startY),Offset(dx-15,ground-80),Paint()..color=beamColor..strokeWidth=2);c.drawLine(Offset(px+25,startY),Offset(dx-15,ground-64),Paint()..color=beamColor..strokeWidth=2);}}
    for(int i=0;i<16;i++){final xx=(i*53.0-scroll*130)%(s.width+20);final yy=s.height*(.2+(i%5)*.1);c.drawCircle(Offset(xx,yy),1.2+(i%2),Paint()..color=const Color(0x88c5ffd4));}
  }
  @override bool shouldRepaint(covariant JunglePainter old)=>old.x!=x||old.jump!=jump||old.scroll!=scroll||old.shooting!=shooting||old.level!=level||old.weapon!=weapon||old.prone!=prone||old.dodging!=dodging;
}
