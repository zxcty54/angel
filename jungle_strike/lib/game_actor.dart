class GameEnemy {
  GameEnemy({required this.x, required this.y, required this.speed, required this.hp, this.boss = false, this.fireIn = 1.2});
  double x, y, speed, fireIn;
  int hp;
  final bool boss;
}

class GameProjectile {
  GameProjectile({required this.x, required this.y, required this.vx, required this.vy, required this.damage, required this.fromEnemy});
  double x, y;
  final double vx, vy;
  final int damage;
  final bool fromEnemy;
}
