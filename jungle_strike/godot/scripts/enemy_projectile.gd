extends Node3D
class_name EnemyProjectile

var velocity := Vector3.ZERO
var target: Node3D
var damage := 10
var time_left := 3.0
var mesh: MeshInstance3D

func _ready() -> void:
	mesh = MeshInstance3D.new()
	var sphere := SphereMesh.new()
	sphere.radius = 0.12
	sphere.height = 0.24
	mesh.mesh = sphere
	var material := StandardMaterial3D.new()
	material.albedo_color = Color(1.0, 0.22, 0.12)
	material.emission_enabled = true
	material.emission = Color(1.0, 0.10, 0.04)
	material.emission_energy_multiplier = 3.5
	mesh.material_override = material
	add_child(mesh)
	var glow := OmniLight3D.new()
	glow.light_color = Color(1.0, 0.16, 0.08)
	glow.light_energy = 0.7
	glow.omni_range = 2.2
	add_child(glow)

func launch(start: Vector3, destination: Vector3, victim: Node3D, damage_amount: int, speed: float) -> void:
	global_position = start
	target = victim
	damage = damage_amount
	velocity = (destination - start).normalized() * speed

func _physics_process(delta: float) -> void:
	time_left -= delta
	global_position += velocity * delta
	if is_instance_valid(target) and global_position.distance_to(target.global_position + Vector3.UP) < 0.9:
		if target.has_method("take_damage"):
			target.take_damage(damage)
		queue_free()
	elif time_left <= 0.0:
		queue_free()
