import 'dart:async';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'game_actor.dart';
import 'fighter_painter.dart';

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
      Image.asset('assets/jungle_frontier.png', fit: BoxFit.cover, filterQuality: FilterQuality.none),
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
  Timer? timer, jumpTimer;
  double x = .16, jump = 0, scroll = 0, fireCooldown = 0, spawnCooldown = 0, invulnerable = 0, moveAxis = 0, fireRate = 1, cameraShake = 0, idleSeconds = 0;
  Offset aimAxis = Offset.zero;
  bool _stickUpActive = false, pausedForUpgrade = false, doubleJump = false;
  int shieldCharges = 0, damageBonus = 0, jumpUses = 0, hitStopFrames = 0;
  int score = 0, armor = 3, level = 1, bossHp = 10, killsThisMission = 0, frame = 0, spawnIndex = 0;
  int unlockedMission = 1, bestScore = 0;
  bool running = false, firing = false, campaignWon = false;
  bool prone = false, dodging = false, dodgeReady = true, bossSpawned = false;
  String weapon = 'PULSE', emote = '';
  final List<GameEnemy> enemies = [];
  final List<GameDeath> deaths = [];
  final List<GameProjectile> projectiles = [];
  static const _weapons = ['PISTOL', 'PULSE', 'SPREAD', 'ROCKET'];
  static const _emotes = ['💪', '🔥', '😎', '❤️'];

  @override
  void initState() {
    super.initState();
    _restoreProgress();
  }

  Future<void> _restoreProgress() async {
    final prefs = await SharedPreferences.getInstance();
    if (!mounted) { return; }
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
    if (mounted && latestBest != bestScore) { setState(() => bestScore = latestBest); }
  }

  void start() {
    setState(() {
      running = true;
      campaignWon = false;
      score = 0;
      armor = 3;
      x = .16;
      moveAxis = 0;
      aimAxis = Offset.zero;
      fireRate = 1;
      shieldCharges = 0;
      damageBonus = 0;
      doubleJump = false;
      jumpUses = 0;
      hitStopFrames = 0;
      cameraShake = 0;
      idleSeconds = 0;
      pausedForUpgrade = false;
      scroll = 0;
      frame = 0;
      spawnIndex = 0;
      fireCooldown = 0;
      spawnCooldown = .35;
      invulnerable = 0;
      killsThisMission = 0;
      level = unlockedMission;
      bossHp = 12;
      bossSpawned = false;
      enemies.clear();
      deaths.clear();
      projectiles.clear();
      prone = false;
      dodging = false;
      weapon = 'PULSE';
      emote = '';
    });
    timer?.cancel();
    timer = Timer.periodic(const Duration(milliseconds: 50), (_) => _step());
  }

  void _step() {
    if (!mounted || !running || pausedForUpgrade) { return; }
    if (hitStopFrames > 0) { hitStopFrames--; return; }
    var save = false;
    var offerUpgrade = false;
    const dt = .05;
    setState(() {
      frame++;
      scroll = (scroll + dt * .22) % 1;
      x = (x + moveAxis * dt * .72).clamp(.05, .72).toDouble();
      fireCooldown -= dt;
      spawnCooldown -= dt;
      invulnerable = math.max(0, invulnerable - dt).toDouble();
      cameraShake = math.max(0, cameraShake - dt * 2.8).toDouble();
      if (moveAxis.abs() < .08 && aimAxis.distance < .2 && !firing && jump == 0 && !prone && !dodging) { idleSeconds += dt; } else { idleSeconds = 0; }
      final playerY = .70 - jump * .20;

      // Zero right-stick input softly locks on to the nearest enemy. Dragging
      // the right stick switches to direct manual aim.
      var shotDirection = aimAxis;
      if (shotDirection.distance < .2) {
        GameEnemy? nearest;
        var nearestDistance = double.infinity;
        for (final enemy in enemies) {
          if (enemy.x < x - .02) { continue; }
          final dx = enemy.x - x;
          final dy = enemy.y - playerY;
          final distance = dx * dx + dy * dy;
          if (distance < nearestDistance) { nearest = enemy; nearestDistance = distance; }
        }
        final targetX = nearest?.x;
        final targetY = nearest?.y;
        if (targetX == null || targetY == null) {
          shotDirection = const Offset(1, 0);
        } else {
          shotDirection = Offset(targetX - x, targetY - playerY);
        }
      }
      final aimLength = math.max(.001, shotDirection.distance);
      shotDirection = shotDirection / aimLength;

      // Hold FIRE to emit real, moving projectiles. Each weapon has different
      // cadence, spread, damage and muzzle feedback.
      if (firing && fireCooldown <= 0) {
        final damage = (weapon == 'ROCKET' ? 4 : 1) + damageBonus;
        final speed = weapon == 'ROCKET' ? 1.05 : weapon == 'PISTOL' ? 1.95 : 1.65;
        final originX = x + (shotDirection.dx < -.1 ? -.03 : weapon == 'PISTOL' ? .14 : .20);
        projectiles.add(GameProjectile(x: originX, y: playerY, vx: shotDirection.dx * speed, vy: shotDirection.dy * speed, damage: damage, fromEnemy: false));
        if (weapon == 'SPREAD') {
          final angle = math.atan2(shotDirection.dy, shotDirection.dx);
          for (final offset in [-.22, .22]) {
            final pelletAngle = angle + offset;
            projectiles.add(GameProjectile(x: originX, y: playerY, vx: math.cos(pelletAngle) * 1.35, vy: math.sin(pelletAngle) * 1.35, damage: 1 + damageBonus, fromEnemy: false));
          }
        }
        fireCooldown = (weapon == 'ROCKET' ? .55 : weapon == 'PISTOL' ? .28 : weapon == 'SPREAD' ? .30 : .16) * fireRate;
      }

      // Four regular enemies clear a mission. The last mission adds a boss
      // with a large health pool and its own projectile attacks.
      if (spawnCooldown <= 0 && enemies.length < 4 && !(level == 6 && bossSpawned)) {
        spawnIndex++;
        final barrel = spawnIndex % 5 == 0;
        final flyer = !barrel && spawnIndex % 3 == 0;
        enemies.add(GameEnemy(x: 1.08, y: barrel ? .73 : flyer ? .53 : .70, speed: barrel ? .06 : flyer ? .20 : .13, hp: barrel ? 2 : flyer ? 2 : 1, explosive: barrel, fireIn: barrel ? 99 : flyer ? .9 : 1.35));
        spawnCooldown = level == 6 ? .95 : 1.25;
      }
      if (level == 6 && killsThisMission >= 2 && !bossSpawned) {
        enemies.add(GameEnemy(x: 1.08, y: .58, speed: .045, hp: 12, boss: true, fireIn: .65));
        bossSpawned = true;
      }

      for (final enemy in enemies) {
        enemy.flashFor = math.max(0, enemy.flashFor - dt).toDouble();
        enemy.x -= enemy.speed * dt;
        if (!enemy.boss && enemy.y < .6 && enemy.x < .82) { enemy.y = math.min(.70, enemy.y + dt * .16).toDouble(); }
        enemy.fireIn -= dt;
        if (!enemy.explosive && enemy.fireIn <= 0 && enemy.x < .92) {
          final targetY = prone ? .75 : playerY;
          if (enemy.boss) {
            // Three-lane fan volley with a telegraph gap between patterns.
            for (final lane in [-1, 0, 1]) {
              projectiles.add(GameProjectile(x: enemy.x - .09, y: enemy.y, vx: -.62, vy: (targetY - enemy.y) * .2 + lane * .33, damage: 1, fromEnemy: true));
            }
            enemy.fireIn = .85;
          } else {
            projectiles.add(GameProjectile(x: enemy.x - .035, y: enemy.y, vx: -.72, vy: (targetY - enemy.y) * .32, damage: 1, fromEnemy: true));
            enemy.fireIn = 1.5;
          }
        }
      }

      for (final death in deaths) {
        death.x += death.vx * dt;
        death.vy += 1.25 * dt;
        death.y += death.vy * dt;
        death.rotation += death.vx * dt * 2.4;
        death.life -= dt;
        if (death.y >= .70 && death.bounces == 0) { death.y = .70; death.vy = -.24; death.vx *= .62; death.bounces++; }
      }
      deaths.removeWhere((death) => death.life <= 0);

      for (final bullet in projectiles) {
        bullet.x += bullet.vx * dt;
        bullet.y += bullet.vy * dt;
      }
      projectiles.removeWhere((b) => b.x < -.1 || b.x > 1.2 || b.y < .1 || b.y > 1);

      // Player shots hit enemies; enemy shots and contact can hurt the player.
      for (final bullet in projectiles.where((b) => !b.fromEnemy).toList()) {
        GameEnemy? target;
        for (final enemy in enemies) {
          if ((enemy.x - bullet.x).abs() < (enemy.boss ? .09 : .055) &&
              (enemy.y - bullet.y).abs() < (enemy.boss ? .18 : .12)) {
            target = enemy;
            break;
          }
        }
        if (target == null) { continue; }
        final hitTarget = target;
        hitTarget.hp -= bullet.damage;
          hitTarget.flashFor = .1;
          projectiles.remove(bullet);
          if (hitTarget.boss) bossHp = hitTarget.hp;
          if (hitTarget.hp <= 0) {
            deaths.add(GameDeath(x: hitTarget.x, y: hitTarget.y, vx: .45 + bullet.vx.abs()*.2, vy: -.55, rotation: -.2));
            enemies.remove(hitTarget);
            score += hitTarget.boss ? 1500 : 100;
            if (hitTarget.explosive) {
              cameraShake = .95;
              hitStopFrames = 4;
              // Snapshot coordinates before the predicate closure.
              final blastX = hitTarget.x;
              final blastY = hitTarget.y;
              for (final victim in enemies.where((e) => (e.x-blastX).abs()<.25 && (e.y-blastY).abs()<.2).toList()) {
                if (victim.boss) {
                  victim.hp -= 3;
                  bossHp = victim.hp;
                  if (victim.hp <= 0) { enemies.remove(victim); running = false; campaignWon = true; save = true; }
                } else {
                  deaths.add(GameDeath(x: victim.x, y: victim.y, vx: .62, vy: -.7, rotation: -.3));
                  enemies.remove(victim);
                  score += 100;
                  killsThisMission++;
                }
              }
            }
            cameraShake = hitTarget.boss ? 1.0 : hitTarget.explosive ? .95 : .42;
            hitStopFrames = hitTarget.boss ? 5 : 2;
            if (hitTarget.boss) {
              running = false;
              campaignWon = true;
              save = true;
            } else {
              killsThisMission++;
              if (level < 6 && killsThisMission >= 4) {
                level++;
                unlockedMission = math.max(unlockedMission, level).toInt();
                killsThisMission = 0;
                spawnCooldown = .8;
                save = true;
                if (level < 6) { offerUpgrade = true; }
              }
            }
          }
      }

      for (final bullet in projectiles.where((b) => b.fromEnemy).toList()) {
        final verticalHit = prone ? bullet.y > .69 : (bullet.y - playerY).abs() < .12;
        if ((bullet.x - x).abs() < .045 && verticalHit && !dodging && invulnerable <= 0) {
          projectiles.remove(bullet);
          _takeHit();
          if (armor <= 0) { running = false; save = true; }
        }
      }

      for (final enemy in enemies.toList()) {
        final verticalHit = prone ? enemy.y > .65 : (enemy.y - playerY).abs() < .14;
        if ((enemy.x - x).abs() < (enemy.boss ? .08 : .045) && verticalHit && !dodging && invulnerable <= 0) {
          _takeHit();
          enemy.x += .12;
          if (armor <= 0) { running = false; save = true; }
        }
      }
      enemies.removeWhere((e) => e.x < -.15 && !e.boss);
      if (score > bestScore && score % 100 == 0) { save = true; }
    });
    if (save) { _saveProgress(); }
    if (offerUpgrade) { _showUpgrade(); }
  }

  void _takeHit() {
    cameraShake = .75;
    invulnerable = .9;
    if (shieldCharges > 0) {
      shieldCharges--;
    } else {
      armor--;
    }
  }

  Future<void> _showUpgrade() async {
    const pool = ['WIDE SPREAD', 'HOT ROUNDS', 'SHIELD DRONE', 'QUICK TRIGGER', 'DOUBLE JUMP'];
    final choices = [...pool]..shuffle(math.Random(level * 91 + score));
    setState(() => pausedForUpgrade = true);
    final selected = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: const Color(0xff172432),
        title: const Text('MISSION CLEAR · PICK AN UPGRADE', style: TextStyle(color: Color(0xffffd166), fontSize: 16, fontWeight: FontWeight.w900)),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          for (final choice in choices.take(3))
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: SizedBox(width: double.infinity, child: OutlinedButton(
                onPressed: () => Navigator.pop(dialogContext, choice),
                child: Text(switch (choice) {
                  'WIDE SPREAD' => 'WIDE SPREAD · 3-shot fan',
                  'HOT ROUNDS' => 'HOT ROUNDS · bonus damage',
                  'SHIELD DRONE' => 'SHIELD DRONE · absorb 2 hits',
                  'QUICK TRIGGER' => 'QUICK TRIGGER · faster fire',
                  _ => 'DOUBLE JUMP · extra air jump',
                }),
              )),
            ),
        ]),
      ),
    );
    if (!mounted) { return; }
    setState(() {
      pausedForUpgrade = false;
      switch (selected) {
        case 'WIDE SPREAD': weapon = 'SPREAD'; break;
        case 'HOT ROUNDS': damageBonus++; break;
        case 'SHIELD DRONE': shieldCharges += 2; break;
        case 'QUICK TRIGGER': fireRate *= .78; break;
        case 'DOUBLE JUMP': doubleJump = true; break;
        default: break;
      }
    });
  }

  void doJump() {
    if (!running) { return; }
    if (jump == 0) { jumpUses = 0; }
    if (jumpUses >= (doubleJump ? 2 : 1)) { return; }
    jumpUses++;
    setState(() { jump = 1; prone = false; idleSeconds = 0; });
    jumpTimer?.cancel();
    jumpTimer = Timer(const Duration(milliseconds: 650), () {
      if (mounted) { setState(() { jump = 0; jumpUses = 0; }); }
    });
  }

  void doDodge() {
    if (!running || !dodgeReady) { return; }
    setState(() { dodging = true; dodgeReady = false; prone = false; idleSeconds = 0; x = (x + .10).clamp(.05, .66).toDouble(); });
    Future.delayed(const Duration(milliseconds: 430), () { if (mounted) { setState(() => dodging = false); } });
    Future.delayed(const Duration(milliseconds: 1200), () { if (mounted) { setState(() => dodgeReady = true); } });
  }

  void cycleWeapon() => setState(() {
    weapon = _weapons[(_weapons.indexOf(weapon) + 1) % _weapons.length];
    idleSeconds = 0;
  });

  void nextEmote() => setState(() {
    emote = _emotes[(_emotes.indexOf(emote) + 1) % _emotes.length];
    idleSeconds = 0;
    Future.delayed(const Duration(milliseconds: 1300), () { if (mounted) { setState(() => emote = ''); } });
  });

  @override
  void dispose() { timer?.cancel(); jumpTimer?.cancel(); super.dispose(); }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(
      title: const Text('JUNGLE STRIKE', style: TextStyle(fontWeight: FontWeight.w900, letterSpacing: 1.3)),
      backgroundColor: const Color(0xff101a25),
      actions: [
        IconButton(
          icon: const Icon(Icons.help_outline),
          onPressed: () => showDialog<void>(
            context: context,
            builder: (c) => const AlertDialog(
              title: Text('How to play'),
              content: Text('Move, jump, hold DOWN to go prone, or dodge to evade. Cycle PULSE, SPREAD and ROCKET weapons. Tap the emote button to cheer! Progress saves at mission checkpoints.'),
            ),
          ),
        ),
      ],
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
          if (shieldCharges > 0) Padding(padding: const EdgeInsets.only(left: 7), child: Text('SHIELD ×$shieldCharges', style: const TextStyle(color: Color(0xff72ffe3), fontSize: 10, fontWeight: FontWeight.w900))),
        ]),
      ),
      if (level == 6 && running) Padding(
        padding: const EdgeInsets.symmetric(horizontal: 18),
        child: ClipRRect(borderRadius: BorderRadius.circular(8), child: LinearProgressIndicator(value: (bossHp / 12).clamp(0, 1).toDouble(), minHeight: 8, color: const Color(0xffef554b), backgroundColor: Colors.white24)),
      ),
      Expanded(child: GestureDetector(
        onTap: running ? null : start,
        child: Stack(fit: StackFit.expand, children: [
          Image.asset(missionBackground(level), fit: BoxFit.cover, filterQuality: FilterQuality.none, errorBuilder: (c, e, s) => const DecoratedBox(decoration: BoxDecoration(gradient: LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: [Color(0xff14283a), Color(0xff385c55), Color(0xff182b30)])))),
          CustomPaint(size: Size.infinite, painter: JunglePainter(x: x, jump: jump, scroll: scroll, shooting: firing, level: level, weapon: weapon, prone: prone, dodging: dodging, enemies: enemies, projectiles: projectiles, deaths: deaths, frame: frame, aimAxis: aimAxis, shake: cameraShake, idleSeconds: idleSeconds, startled: cameraShake > .5)),
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
          FittedBox(
            fit: BoxFit.scaleDown,
            child: Row(mainAxisSize: MainAxisSize.min, children: [
              _VirtualJoystick(onMove: (stick) {
                moveAxis = stick.dx;
                if (stick.distance > .15) { idleSeconds = 0; }
                final wantsJump = stick.dy < -.68;
                if (wantsJump && !_stickUpActive) { doJump(); }
                _stickUpActive = wantsJump;
                final wantsProne = stick.dy > .72;
                if (running && prone != wantsProne) { setState(() => prone = wantsProne); }
              }),
              const SizedBox(width: 10),
              Row(children: [
                control(Icons.arrow_upward_rounded, doJump),
                const SizedBox(width: 5),
                control(Icons.directions_run, doDodge, tint: const Color(0xff42b9a5)),
                const SizedBox(width: 5),
                control(Icons.keyboard_arrow_down, () => setState(() { prone = !prone; idleSeconds = 0; }), tint: const Color(0xff7485ca)),
              ]),
              const SizedBox(width: 10),
              _VirtualJoystick(icon: Icons.gps_fixed, onMove: (stick) { aimAxis = stick; if (stick.distance > .15) { idleSeconds = 0; } }),
              const SizedBox(width: 10),
              GestureDetector(
                onLongPressStart: (_) => setState(() { firing = true; idleSeconds = 0; }),
                onLongPressEnd: (_) => setState(() => firing = false),
                onTapDown: (_) => setState(() { firing = true; idleSeconds = 0; }),
                onTapUp: (_) => setState(() => firing = false),
                child: Container(padding: const EdgeInsets.symmetric(horizontal: 17, vertical: 15), decoration: BoxDecoration(color: const Color(0xffef554b), borderRadius: BorderRadius.circular(16), boxShadow: const [BoxShadow(color: Color(0x88ef554b), blurRadius: 16)]), child: const Row(children: [Icon(Icons.bolt, color: Colors.white), SizedBox(width: 4), Text('FIRE', style: TextStyle(color: Colors.white, fontWeight: FontWeight.w900))])),
              ),
            ]),
          ),
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

class _VirtualJoystick extends StatefulWidget {
  const _VirtualJoystick({required this.onMove, this.icon = Icons.control_camera});
  final ValueChanged<Offset> onMove;
  final IconData icon;
  @override
  State<_VirtualJoystick> createState() => _VirtualJoystickState();
}

class _VirtualJoystickState extends State<_VirtualJoystick> {
  Offset _axis = Offset.zero;

  void _update(Offset position, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    var axis = Offset((position.dx - center.dx) / 34, (position.dy - center.dy) / 34);
    final length = axis.distance;
    if (length > 1) { axis = axis / length; }
    setState(() => _axis = axis);
    widget.onMove(axis);
  }

  void _release() {
    setState(() => _axis = Offset.zero);
    widget.onMove(Offset.zero);
  }

  @override
  Widget build(BuildContext context) => SizedBox.square(
    dimension: 108,
    child: LayoutBuilder(builder: (context, box) {
      final size = Size(box.maxWidth, box.maxHeight);
      return GestureDetector(
        behavior: HitTestBehavior.opaque,
        onPanStart: (event) => _update(event.localPosition, size),
        onPanUpdate: (event) => _update(event.localPosition, size),
        onPanEnd: (_) => _release(),
        onPanCancel: _release,
        child: CustomPaint(
          painter: const _JoystickTrackPainter(),
          child: Center(
            child: Transform.translate(
              offset: Offset(_axis.dx * 29, _axis.dy * 29),
              child: Container(
                width: 43,
                height: 43,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: const LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [Color(0xffd9fff7), Color(0xff38bcae), Color(0xff176f77)]),
                  border: Border.all(color: Colors.white70, width: 1.5),
                  boxShadow: const [BoxShadow(color: Color(0x9940e0d0), blurRadius: 16, spreadRadius: 1)],
                ),
                child: Icon(widget.icon, color: const Color(0xff103740), size: 25),
              ),
            ),
          ),
        ),
      );
    }),
  );
}

class _JoystickTrackPainter extends CustomPainter {
  const _JoystickTrackPainter();
  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    canvas.drawCircle(center, 51, Paint()..shader = const RadialGradient(colors: [Color(0x6636d1c0), Color(0x22202e44), Color(0x99101a28)]).createShader(Offset.zero & size));
    canvas.drawCircle(center, 48, Paint()..style = PaintingStyle.stroke..strokeWidth = 1.5..color = Colors.white38);
    canvas.drawCircle(center, 34, Paint()..style = PaintingStyle.stroke..strokeWidth = 1..color = const Color(0x667be7d7));
    canvas.drawCircle(center, 3, Paint()..color = Colors.white54);
  }
  @override
  bool shouldRepaint(covariant _JoystickTrackPainter oldDelegate) => false;
}

class JunglePainter extends CustomPainter {
  JunglePainter({required this.x, required this.jump, required this.scroll, required this.shooting, required this.level, required this.weapon, required this.prone, required this.dodging, required this.enemies, required this.projectiles, required this.deaths, required this.frame, required this.aimAxis, required this.shake, required this.idleSeconds, required this.startled});
  final double x, jump, scroll, shake, idleSeconds; final bool shooting, prone, dodging, startled; final int level, frame; final String weapon; final Offset aimAxis;
  final List<GameEnemy> enemies;
  final List<GameProjectile> projectiles;
  final List<GameDeath> deaths;
  @override
  void paint(Canvas c, Size s) {
    c.save();
    if (enemies.any((enemy) => enemy.boss)) {
      c.translate(s.width * .07, s.height * .055);
      c.scale(.86);
    }
    if (shake > 0) { c.translate(math.sin(frame * 2.7) * shake * 8, math.cos(frame * 3.1) * shake * 5); }
    final ground = s.height * .78;
    // Five independently scrolling planes create layered 2.5D parallax depth.
    c.drawRect(Offset.zero & s, Paint()..shader = const LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: [Color(0xff142b43), Color(0xff59717b), Color(0xffb68b61)]).createShader(Offset.zero & s));
    for (int i=0; i<5; i++) {
      final factor = .025 + i*.045;
      final yBase = s.height*(.36+i*.075);
      final color = [const Color(0xff304b61),const Color(0xff425c61),const Color(0xff4a5148),const Color(0xff374638),const Color(0xff202d27)][i];
      for (int j=0;j<6;j++) {
        final xx=((j*s.width/4-scroll*s.width*factor)%(s.width+120))-60;
        final width=s.width*(.22+i*.035);
        final height=s.height*(.1+(j%3)*.045);
        final rect=Rect.fromLTWH(xx,yBase-height,width,height);
        if (i<2) { final hill=Path()..moveTo(rect.left,rect.bottom)..quadraticBezierTo(rect.center.dx,rect.top,rect.right,rect.bottom)..close(); c.drawPath(hill,Paint()..color=color); }
        else { c.drawRect(rect,Paint()..color=color); for(int w=0;w<4;w++){c.drawRect(Rect.fromLTWH(xx+8+w*13,yBase-height+8,5,8),Paint()..color=const Color(0x557ed2c0));} }
      }
    }
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
    final px = s.width * x;
    final footY = ground - jump * 65;
    final unit = (s.shortestSide / 360).clamp(.85, 1.3).toDouble();
    final py = footY - 55 * unit;
    paintFighter(
      c,
      x: px,
      footY: footY,
      scale: unit,
      frame: frame,
      prone: prone,
      dodging: dodging,
      firing: shooting,
      weapon: weapon,
      idleSeconds: idleSeconds,
      startled: startled,
    );

    for (final enemy in enemies) {
      final center = Offset(s.width * enemy.x, s.height * enemy.y);
      if (enemy.boss) {
        final pulse = 1 + math.sin(frame * .16) * .05;
        final w = s.width * .16 * pulse;
        c.drawCircle(center, w * .72, Paint()..color = const Color(0x99ff514b)..maskFilter = const MaskFilter.blur(BlurStyle.normal, 24));
        c.drawRRect(RRect.fromRectAndRadius(Rect.fromCenter(center: center, width: w, height: w * .72), const Radius.circular(18)), Paint()..shader = const LinearGradient(colors: [Color(0xffff8655), Color(0xff8b2344)]).createShader(Rect.fromCenter(center: center, width: w, height: w * .72)));
        c.drawCircle(Offset(center.dx - w * .16, center.dy - 3), 5, Paint()..color = const Color(0xffffe29b));
        c.drawCircle(Offset(center.dx + w * .16, center.dy - 3), 5, Paint()..color = const Color(0xffffe29b));
        c.drawLine(Offset(center.dx - w * .62, center.dy - 8), Offset(center.dx + w * .62, center.dy - 8), Paint()..color = const Color(0xffffc857)..strokeWidth = 5);
      } else if (enemy.explosive) {
        final box = Rect.fromCenter(center: center, width: 32, height: 34);
        c.drawRect(box, Paint()..color = const Color(0xff603f2c));
        c.drawRect(Rect.fromLTWH(box.left+4,box.top+4,24,26), Paint()..color = const Color(0xffa66a37));
        c.drawRect(Rect.fromLTWH(box.left+4,box.top+13,24,5), Paint()..color = const Color(0xffe2bd68));
        c.drawRect(Rect.fromLTWH(box.left+13,box.top+4,6,26), Paint()..color = const Color(0xff4f3a2c));
        c.drawRect(Rect.fromLTWH(center.dx-3,box.top-8,6,8), Paint()..color = const Color(0xffff7548));
      } else if (enemy.y < .6) {
        c.drawCircle(center, 17, Paint()..color = const Color(0x88ff614c)..maskFilter = const MaskFilter.blur(BlurStyle.normal, 12));
        c.drawRRect(RRect.fromRectAndRadius(Rect.fromCenter(center: center, width: 34, height: 17), const Radius.circular(7)), Paint()..color = const Color(0xffdf584c));
        c.drawCircle(Offset(center.dx + 5, center.dy - 2), 3, Paint()..color = const Color(0xffffe9a4));
        c.drawLine(Offset(center.dx - 23, center.dy), Offset(center.dx + 23, center.dy), Paint()..color = const Color(0xffd7dce0)..strokeWidth = 3);
      } else {
        c.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(center.dx - 9, center.dy - 23, 18, 25), const Radius.circular(4)), Paint()..color = const Color(0xffe6574e));
        c.drawCircle(Offset(center.dx, center.dy - 28), 8, Paint()..color = const Color(0xffd8ad83));
        c.drawRect(Rect.fromLTWH(center.dx + 5, center.dy - 17, 20, 4), Paint()..color = const Color(0xffdce6e1));
        c.drawRect(Rect.fromLTWH(center.dx - 8, center.dy + 1, 5, 13), Paint()..color = const Color(0xff394551));
        c.drawRect(Rect.fromLTWH(center.dx + 3, center.dy + 1, 5, 13), Paint()..color = const Color(0xff394551));
      }
      if (enemy.flashFor > 0) {
        c.drawCircle(center, enemy.boss ? 42 : 24, Paint()..color = Colors.white.withOpacity((enemy.flashFor/.1).clamp(0,1)*.85)..maskFilter = const MaskFilter.blur(BlurStyle.normal, 8));
      }
      if (enemy.hp > 1) {
        c.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(center.dx - 20, center.dy - (enemy.boss ? 38 : 39), 40, 4), const Radius.circular(2)), Paint()..color = Colors.white24);
        c.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(center.dx - 20, center.dy - (enemy.boss ? 38 : 39), 40 * (enemy.hp / (enemy.boss ? 12 : 2)).clamp(0, 1), 4), const Radius.circular(2)), Paint()..color = const Color(0xffff6961));
      }
    }
    for (final death in deaths) {
      final center=Offset(s.width*death.x,s.height*death.y);
      c.save(); c.translate(center.dx,center.dy); c.rotate(death.rotation);
      final fade=death.life.clamp(0,1);
      c.drawRRect(RRect.fromRectAndRadius(const Rect.fromLTWH(-12,-20,24,36),const Radius.circular(5)),Paint()..color=Color.fromARGB((255*fade).round(),0xe6,0x68,0x50));
      c.drawCircle(const Offset(0,-24),8,Paint()..color=Color.fromARGB((255*fade).round(),0xd8,0xad,0x83));
      c.restore();
      for(int p=0;p<3;p++){final a=frame*.31+p*2.1;c.drawCircle(center+Offset(math.cos(a)*18,math.sin(a)*12),2.3,Paint()..color=const Color(0xffffc857)..maskFilter=const MaskFilter.blur(BlurStyle.normal,4));}
    }
    for (final bullet in projectiles) {
      final pos = Offset(s.width * bullet.x, s.height * bullet.y);
      final color = bullet.fromEnemy ? const Color(0xffff5955) : weapon == 'ROCKET' ? const Color(0xffffa451) : weapon == 'SPREAD' ? const Color(0xff77eaff) : const Color(0xffffe680);
      c.drawCircle(pos, bullet.fromEnemy ? 5 : weapon == 'ROCKET' ? 8 : 4, Paint()..color = color..maskFilter = const MaskFilter.blur(BlurStyle.normal, 5));
      c.drawCircle(pos, bullet.fromEnemy ? 2.5 : 2, Paint()..color = Colors.white);
    }
    if (shooting) {
      final muzzle=Offset(px + (prone ? 70 : 78) * unit, prone ? footY - 37 * unit : py);
      c.drawCircle(muzzle, weapon == 'ROCKET' ? 34 : 20, Paint()..color=(weapon == 'ROCKET' ? const Color(0x66ff8a3d) : const Color(0x66ffe58a))..maskFilter=const MaskFilter.blur(BlurStyle.normal,18));
      c.drawCircle(muzzle, weapon == 'ROCKET' ? 8 : 4, Paint()..color = weapon == 'ROCKET' ? const Color(0xffffa451) : const Color(0xfffff0ae));
    }
    if (aimAxis.distance > .2) {
      final muzzle = Offset(px + (prone ? 70 : 78) * unit, prone ? footY - 37 * unit : py);
      final reticle = muzzle + aimAxis * (s.width * .28);
      final aimPaint = Paint()..color = const Color(0x99bafcf1)..strokeWidth = 1.5;
      c.drawLine(muzzle, reticle, aimPaint..color = const Color(0x558fffee));
      c.drawLine(Offset(reticle.dx-8,reticle.dy),Offset(reticle.dx+8,reticle.dy),aimPaint);
      c.drawLine(Offset(reticle.dx,reticle.dy-8),Offset(reticle.dx,reticle.dy+8),aimPaint);
      c.drawCircle(reticle, 4, aimPaint..style=PaintingStyle.stroke);
    }
    for(int i=0;i<16;i++){final xx=(i*53.0-scroll*130)%(s.width+20);final yy=s.height*(.2+(i%5)*.1);c.drawCircle(Offset(xx,yy),1.2+(i%2),Paint()..color=const Color(0x88c5ffd4));}
    // Near-camera grass and broken posts move fastest and briefly cross the actor.
    for(int i=0;i<14;i++){
      final xx=((i*91.0-scroll*560)%(s.width+80))-35; final y=ground+8+(i%3)*11;
      final p=Path()..moveTo(xx,y+24)..quadraticBezierTo(xx-13,y+6,xx-4,y-6)..quadraticBezierTo(xx+1,y+8,xx+4,y+24)..close();
      c.drawPath(p,Paint()..color=i.isEven?const Color(0xff6b8b55):const Color(0xff415c3e));
    }
    c.restore();
  }
  @override bool shouldRepaint(covariant JunglePainter old)=>old.x!=x||old.jump!=jump||old.scroll!=scroll||old.shooting!=shooting||old.level!=level||old.weapon!=weapon||old.prone!=prone||old.dodging!=dodging||old.frame!=frame||old.aimAxis!=aimAxis||old.shake!=shake||old.idleSeconds!=idleSeconds||old.startled!=startled||old.deaths!=deaths||old.enemies!=enemies||old.projectiles!=projectiles;
}
