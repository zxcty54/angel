class GameEnemy {
  GameEnemy({required this.x, required this.y, required this.speed, required this.hp, this.boss = false, this.explosive = false, this.fireIn = 1.2});
  double x, y, speed, fireIn, flashFor = 0;
  int hp;
  final bool boss, explosive;
}

class GameDeath {
  GameDeath({required this.x, required this.y, required this.vx, required this.vy, required this.rotation, this.bounces = 0});
  double x, y, vx, vy, rotation;
  int bounces;
  double life = 1.4;
}

class GameProjectile {
  GameProjectile({required this.x, required this.y, required this.vx, required this.vy, required this.damage, required this.fromEnemy});
  double x, y;
  final double vx, vy;
  final int damage;
  final bool fromEnemy;
}
