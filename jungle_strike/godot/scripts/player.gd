extends CharacterBody3D
class_name JunglePlayer

signal health_changed(current: int, maximum: int)

const TOUCH_CONTROLS := preload("res://scripts/touch_controls.gd")

@export var move_speed := 5.2
@export var acceleration := 18.0
@export var jump_velocity := 5.2
@export var look_sensitivity := 0.003

@onready var pivot: Node3D = $CameraPivot
@onready var spring_arm: SpringArm3D = $CameraPivot/SpringArm3D
@onready var camera: Camera3D = $CameraPivot/SpringArm3D/Camera3D
@onready var gun: MeshInstance3D = $Gun
@onready var scarf_tail: MeshInstance3D = $BandanaTail
@onready var left_leg: MeshInstance3D = $LeftLeg
@onready var right_leg: MeshInstance3D = $RightLeg

var gravity: float = ProjectSettings.get_setting("physics/3d/default_gravity")
var pitch := -0.12
var shot_cooldown := 0.0
var touch_move := Vector2.ZERO
var touch_fire := false
var dodge_time := 0.0
var dodge_cooldown := 0.0
var anim_time := 0.0
var health := 100
var max_health := 100
var bonus_damage := 0
var trigger_rate := 0.16
var alive := true

func _ready() -> void:
	Input.mouse_mode = Input.MOUSE_MODE_VISIBLE
	(camera.get_node("AimRay") as RayCast3D).add_exception(self)
	_add_action("move_forward", KEY_W)
	_add_action("move_back", KEY_S)
	_add_action("move_left", KEY_A)
	_add_action("move_right", KEY_D)
	_add_action("jump", KEY_SPACE)
	_add_action("fire", KEY_F)
	if OS.has_feature("mobile"):
		var controls_layer := CanvasLayer.new()
		controls_layer.name = "TouchControlsLayer"
		get_tree().current_scene.add_child(controls_layer)
		var controls := TOUCH_CONTROLS.new()
		controls_layer.add_child(controls)
		controls.move_changed.connect(func(value: Vector2): touch_move = value)
		controls.fire_changed.connect(func(pressed: bool): touch_fire = pressed)
		controls.jump_pressed.connect(_jump)
		controls.dodge_pressed.connect(_dodge)
		controls.look_changed.connect(_touch_look)

func _add_action(action: String, keycode: int) -> void:
	if not InputMap.has_action(action):
		InputMap.add_action(action)
	for existing in InputMap.action_get_events(action):
		if existing is InputEventKey and existing.physical_keycode == keycode:
			return
	var event := InputEventKey.new()
	event.physical_keycode = keycode
	InputMap.action_add_event(action, event)

func _unhandled_input(event: InputEvent) -> void:
	if event is InputEventMouseMotion and Input.mouse_mode == Input.MOUSE_MODE_CAPTURED:
		pivot.rotation.y -= event.relative.x * look_sensitivity
		pitch = clampf(pitch - event.relative.y * look_sensitivity, -0.85, 0.3)
		pivot.rotation.x = pitch
	elif event is InputEventMouseButton and event.pressed:
		if event.button_index == MOUSE_BUTTON_LEFT:
			if Input.mouse_mode == Input.MOUSE_MODE_VISIBLE:
				Input.mouse_mode = Input.MOUSE_MODE_CAPTURED
			_fire()
	elif event is InputEventKey and event.pressed and event.keycode == KEY_ESCAPE:
		Input.mouse_mode = Input.MOUSE_MODE_VISIBLE

func _physics_process(delta: float) -> void:
	anim_time += delta
	shot_cooldown = maxf(0.0, shot_cooldown - delta)
	dodge_time = maxf(0.0, dodge_time - delta)
	dodge_cooldown = maxf(0.0, dodge_cooldown - delta)
	if not is_on_floor():
		velocity.y -= gravity * delta
	elif Input.is_action_just_pressed("jump"):
		_jump()
	var input := Input.get_vector("move_left", "move_right", "move_forward", "move_back")
	if touch_move.length_squared() > 0.01:
		input = touch_move
	var forward := -pivot.global_basis.z
	var right := pivot.global_basis.x
	forward.y = 0
	right.y = 0
	forward = forward.normalized()
	right = right.normalized()
	var direction := (right * input.x + forward * input.y).normalized()
	var target_velocity := direction * move_speed
	var run_phase := anim_time * (10.0 if direction.length_squared() > 0.01 else 2.0)
	left_leg.rotation.x = sin(run_phase) * 0.48 * input.length()
	right_leg.rotation.x = -sin(run_phase) * 0.48 * input.length()
	scarf_tail.rotation.z = sin(anim_time * 7.0) * (0.12 + input.length() * 0.26)
	scarf_tail.rotation.x = cos(anim_time * 5.0) * 0.12
	velocity.x = move_toward(velocity.x, target_velocity.x, acceleration * delta)
	velocity.z = move_toward(velocity.z, target_velocity.z, acceleration * delta)
	if dodge_time > 0.0:
		velocity.x = -pivot.global_basis.z.x * 12.0
		velocity.z = -pivot.global_basis.z.z * 12.0
	if direction.length_squared() > 0.01:
		rotation.y = lerp_angle(rotation.y, atan2(-direction.x, -direction.z), 10.0 * delta)
	move_and_slide()
	if Input.is_action_pressed("fire") or touch_fire:
		_fire()

func _jump() -> void:
	if is_on_floor():
		velocity.y = jump_velocity

func _dodge() -> void:
	if dodge_cooldown <= 0.0:
		dodge_time = 0.22
		dodge_cooldown = 1.15

func set_boss_camera(enabled: bool) -> void:
	var tween := create_tween()
	tween.tween_property(spring_arm, "spring_length", 7.2 if enabled else 5.0, 0.8).set_trans(Tween.TRANS_SINE).set_ease(Tween.EASE_IN_OUT)

func _touch_look(delta: Vector2) -> void:
	pivot.rotation.y -= delta.x * look_sensitivity * 1.7
	pitch = clampf(pitch - delta.y * look_sensitivity * 1.7, -0.85, 0.3)
	pivot.rotation.x = pitch

func _fire() -> void:
	if shot_cooldown > 0.0 or not alive:
		return
	shot_cooldown = trigger_rate
	var ray := camera.get_node("AimRay") as RayCast3D
	ray.force_raycast_update()
	if ray.is_colliding():
		var collider := ray.get_collider()
		if collider != null and collider.has_method("take_damage"):
			collider.take_damage(1 + bonus_damage)
		var hit := ray.get_collision_point()
		var tracer := MeshInstance3D.new()
		var line := CylinderMesh.new()
		line.top_radius = 0.018
		line.bottom_radius = 0.018
		line.height = camera.global_position.distance_to(hit)
		tracer.mesh = line
		tracer.material_override = _glow_material(Color(1.0, 0.72, 0.28))
		tracer.global_position = (camera.global_position + hit) * 0.5
		tracer.look_at(hit, Vector3.UP)
		get_tree().current_scene.add_child(tracer)
		var tracer_timer := get_tree().create_timer(0.055)
		tracer_timer.timeout.connect(tracer.queue_free)
	var flash := OmniLight3D.new()
	flash.light_color = Color(1.0, 0.62, 0.22)
	flash.light_energy = 2.5
	flash.omni_range = 4.0
	flash.position = gun.global_position + -global_basis.z * 0.45
	get_tree().current_scene.add_child(flash)
	var flash_timer := get_tree().create_timer(0.045)
	flash_timer.timeout.connect(flash.queue_free)

func take_damage(amount: int) -> void:
	if not alive or dodge_time > 0.0:
		return
	health = maxi(0, health - amount)
	health_changed.emit(health, max_health)
	if health == 0:
		alive = false
		set_physics_process(false)

func restore_checkpoint() -> void:
	health = max_health
	alive = true
	global_position = Vector3(0, 0.05, 5)
	velocity = Vector3.ZERO
	set_physics_process(true)
	health_changed.emit(health, max_health)

func apply_upgrade(choice: String) -> void:
	match choice:
		"armor":
			max_health += 25
			health = max_health
		"trigger":
			trigger_rate = maxf(0.07, trigger_rate * 0.78)
		"rounds":
			bonus_damage += 1
	health_changed.emit(health, max_health)

func _glow_material(color: Color) -> StandardMaterial3D:
	var material := StandardMaterial3D.new()
	material.albedo_color = color
	material.emission_enabled = true
	material.emission = color
	material.emission_energy_multiplier = 3.0
	return material
