extends CharacterBody3D

const PROJECTILE_SCRIPT := preload("res://scripts/enemy_projectile.gd")

signal defeated

@export var health := 3
@export var walk_speed := 1.8
var player: Node3D
var attack_cooldown := 0.0
var is_boss := false
var gravity: float = ProjectSettings.get_setting("physics/3d/default_gravity")

func setup(target: Node3D, boss: bool = false) -> void:
	player = target
	is_boss = boss
	if boss:
		health = 24
		walk_speed = 1.05
		_scale_up_boss()

func _physics_process(delta: float) -> void:
	if not is_instance_valid(player):
		return
	attack_cooldown = maxf(0.0, attack_cooldown - delta)
	if not is_on_floor():
		velocity.y -= gravity * delta
	var to_player := player.global_position - global_position
	to_player.y = 0
	var distance := to_player.length()
	if distance > 2.2:
		var direction := to_player.normalized()
		velocity.x = direction.x * walk_speed
		velocity.z = direction.z * walk_speed
		rotation.y = atan2(-direction.x, -direction.z)
		if distance < 24.0 and attack_cooldown <= 0.0:
			_shoot_at_player()
			attack_cooldown = 1.0 if is_boss else 1.75
	else:
		velocity.x = move_toward(velocity.x, 0.0, 8.0 * delta)
		velocity.z = move_toward(velocity.z, 0.0, 8.0 * delta)
		if attack_cooldown <= 0.0 and player.has_method("take_damage"):
			player.take_damage(is_boss ? 18 : 10)
			attack_cooldown = 1.1 if is_boss else 1.5
	move_and_slide()

func _shoot_at_player() -> void:
	var start := global_position + Vector3(0, 1.2 * scale.y, 0)
	var target_point := player.global_position + Vector3(0, 1.1, 0)
	var spread := 0.0
	var rounds := 1
	if is_boss:
		spread = 0.12
		rounds = 3
	for i in range(rounds):
		var offset := float(i - (rounds - 1) / 2) * spread
		var destination := target_point + Vector3(offset * 9.0, offset * 2.5, 0)
		var projectile = PROJECTILE_SCRIPT.new()
		get_tree().current_scene.add_child(projectile)
		projectile.launch(start, destination, player, 18 if is_boss else 10, 15.0 if is_boss else 12.0)

func take_damage(amount: int) -> void:
	health -= amount
	_flash_white()
	if health <= 0:
		_spawn_ragdoll()
		defeated.emit()
		queue_free()

func _spawn_ragdoll() -> void:
	var corpse := RigidBody3D.new()
	corpse.name = "FallenEnemy"
	corpse.mass = 2.0 if not is_boss else 5.0
	corpse.position = global_position + Vector3(0, 0.9, 0)
	corpse.rotation = global_rotation
	var mesh_instance := MeshInstance3D.new()
	var mesh := CapsuleMesh.new()
	mesh.radius = 0.42
	mesh.height = 1.8
	mesh_instance.mesh = mesh
	var material := StandardMaterial3D.new()
	material.albedo_color = Color(0.38, 0.22, 0.17) if not is_boss else Color(0.42, 0.11, 0.12)
	material.roughness = 0.8
	mesh_instance.material_override = material
	corpse.add_child(mesh_instance)
	var collider := CollisionShape3D.new()
	var shape := CapsuleShape3D.new()
	shape.radius = 0.42
	shape.height = 1.8
	collider.shape = shape
	corpse.add_child(collider)
	get_parent().add_child(corpse)
	var away := (global_position - player.global_position) if is_instance_valid(player) else Vector3.BACK
	away.y = 0
	away = away.normalized()
	corpse.linear_velocity = away * (5.0 if not is_boss else 7.0) + Vector3.UP * (4.2 if not is_boss else 6.0)
	corpse.angular_velocity = Vector3(randf_range(-5,5), randf_range(-7,7), randf_range(-5,5))
	var expiry := get_tree().create_timer(3.2)
	expiry.timeout.connect(corpse.queue_free)

func _scale_up_boss() -> void:
	scale = Vector3(1.8, 1.8, 1.8)
	var body := get_node("Body") as MeshInstance3D
	var material := StandardMaterial3D.new()
	material.albedo_color = Color(0.42, 0.11, 0.12)
	material.roughness = 0.65
	body.material_override = material

func _flash_white() -> void:
	var body := get_node("Body") as MeshInstance3D
	var original := body.material_override
	var flash := StandardMaterial3D.new()
	flash.albedo_color = Color.WHITE
	body.material_override = flash
	var timer := get_tree().create_timer(0.09)
	timer.timeout.connect(func():
		if is_instance_valid(body):
			body.material_override = original
	)
