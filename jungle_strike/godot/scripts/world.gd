extends Node3D

const PLAYER_SCENE := preload("res://scenes/player.tscn")
const ENEMY_SCENE := preload("res://scenes/enemy.tscn")
const GROUND_SIZE := 180.0
const MISSIONS := ["The Evacuation", "Broken Bridge", "Relay Tower", "Ashen Village", "Storm Pass", "Iron Vulture"]

var player: JunglePlayer
var mission := 1
var kills := 0
var unlocked := 1
var story_label: Label
var hud_label: Label
var health_label: Label
var overlay: PanelContainer
var active := false
var boss_active := false
var save_path := "user://jungle_campaign.cfg"

func _ready() -> void:
	_build_input_map()
	_load_progress()
	_build_landscape()
	_build_cover()
	_build_vegetation_and_field_props()
	player = PLAYER_SCENE.instantiate()
	player.position = Vector3(0, 0.05, 5)
	add_child(player)
	player.health_changed.connect(_on_health_changed)
	_on_health_changed(player.health, player.max_health)
	player.set_physics_process(false)
	_build_hud()
	_update_hud()

func _build_input_map() -> void:
	_add_key("move_forward", KEY_W)
	_add_key("move_back", KEY_S)
	_add_key("move_left", KEY_A)
	_add_key("move_right", KEY_D)
	_add_key("jump", KEY_SPACE)
	_add_key("fire", KEY_F)

func _add_key(action: String, key: int) -> void:
	if not InputMap.has_action(action):
		InputMap.add_action(action)
	var event := InputEventKey.new()
	event.physical_keycode = key
	for existing in InputMap.action_get_events(action):
		if existing is InputEventKey and existing.physical_keycode == key:
			return
	InputMap.action_add_event(action, event)

func _load_progress() -> void:
	var data := ConfigFile.new()
	if data.load(save_path) == OK:
		unlocked = clampi(int(data.get_value("campaign", "unlocked", 1)), 1, MISSIONS.size())
		mission = unlocked

func _save_progress() -> void:
	var data := ConfigFile.new()
	data.set_value("campaign", "unlocked", unlocked)
	data.save(save_path)

func _build_hud() -> void:
	var layer := CanvasLayer.new()
	layer.name = "GameHUD"
	add_child(layer)
	var root := Control.new()
	root.set_anchors_and_offsets_preset(Control.PRESET_FULL_RECT)
	root.mouse_filter = Control.MOUSE_FILTER_IGNORE
	layer.add_child(root)

	hud_label = Label.new()
	hud_label.position = Vector2(24, 20)
	hud_label.add_theme_font_size_override("font_size", 25)
	hud_label.add_theme_color_override("font_color", Color(0.95,0.91,0.74))
	root.add_child(hud_label)
	health_label = Label.new()
	health_label.position = Vector2(24, 58)
	health_label.add_theme_font_size_override("font_size", 20)
	health_label.add_theme_color_override("font_color", Color(0.62,1.0,0.71))
	root.add_child(health_label)
	_add_reticle(root)
	var weapon_label := Label.new()
	weapon_label.text = "RANGER  ·  ASSAULT RIFLE     [F] FIRE  ·  [SPACE] VAULT"
	weapon_label.set_anchors_and_offsets_preset(Control.PRESET_BOTTOM_RIGHT)
	weapon_label.position = Vector2(-430, -48)
	weapon_label.add_theme_font_size_override("font_size", 16)
	weapon_label.add_theme_color_override("font_color", Color(0.88, 0.91, 0.82, 0.95))
	root.add_child(weapon_label)

	overlay = PanelContainer.new()
	overlay.set_anchors_and_offsets_preset(Control.PRESET_CENTER)
	var panel_width := minf(490.0, get_viewport().get_visible_rect().size.x - 28.0)
	overlay.position = Vector2(-panel_width * 0.5, -150)
	overlay.custom_minimum_size = Vector2(panel_width, 300)
	var panel_style := StyleBoxFlat.new()
	panel_style.bg_color = Color(0.035,0.07,0.09,0.94)
	panel_style.border_color = Color(0.66,0.78,0.62,0.8)
	panel_style.set_border_width_all(2)
	panel_style.set_corner_radius_all(16)
	overlay.add_theme_stylebox_override("panel", panel_style)
	root.add_child(overlay)
	_show_intro()

func _show_intro() -> void:
	_clear_overlay()
	var box := _overlay_column()
	var title := Label.new()
	title.text = "JUNGLE STRIKE · OPERATION FRONTIER"
	title.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	title.add_theme_font_size_override("font_size", 19)
	box.add_child(title)
	story_label = Label.new()
	story_label.text = "An Iron Vulture militia has seized the frontier. Lead the evacuation, disable its relay network, and stop the commander. Your campaign and checkpoints stay on this device."
	story_label.autowrap_mode = TextServer.AUTOWRAP_WORD_SMART
	story_label.custom_minimum_size.x = minf(430.0, get_viewport().get_visible_rect().size.x - 70.0)
	box.add_child(story_label)
	var mission_label := Label.new()
	mission_label.text = "CONTINUE · MISSION %d: %s" % [mission, MISSIONS[mission - 1]]
	mission_label.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	box.add_child(mission_label)
	var start := Button.new()
	start.text = "DEPLOY"
	start.custom_minimum_size.y = 54
	start.pressed.connect(_start_campaign)
	box.add_child(start)

func _start_campaign() -> void:
	active = true
	if not OS.has_feature("mobile"):
		Input.mouse_mode = Input.MOUSE_MODE_CAPTURED
	player.set_physics_process(true)
	overlay.visible = false
	if mission == MISSIONS.size():
		_spawn_guards(2)
	else:
		_spawn_guards(4)
	_update_hud()

func _spawn_guards(count: int) -> void:
	for i in range(count):
		var enemy = ENEMY_SCENE.instantiate()
		var angle := TAU * float(i) / float(count) + 0.55
		enemy.position = Vector3(cos(angle) * 18.0, 0.05, -12.0 + sin(angle) * 12.0)
		add_child(enemy)
		enemy.setup(player)
		enemy.defeated.connect(_on_enemy_defeated)

func _spawn_boss() -> void:
	boss_active = true
	player.set_boss_camera(true)
	var enemy = ENEMY_SCENE.instantiate()
	enemy.position = Vector3(0, 0.05, -24)
	add_child(enemy)
	enemy.setup(player, true)
	enemy.defeated.connect(_on_boss_defeated)
	_update_hud()

func _on_enemy_defeated() -> void:
	kills += 1
	if mission == MISSIONS.size():
		if kills >= 2 and not boss_active:
			_spawn_boss()
	else:
		if kills >= 4:
			mission += 1
			unlocked = maxi(unlocked, mission)
			_save_progress()
			active = false
			player.set_physics_process(false)
			_show_upgrade()
	_update_hud()

func _on_boss_defeated() -> void:
	active = false
	player.set_physics_process(false)
	unlocked = MISSIONS.size()
	_save_progress()
	_show_victory()

func _show_upgrade() -> void:
	Input.mouse_mode = Input.MOUSE_MODE_VISIBLE
	overlay.visible = true
	_clear_overlay()
	var box := _overlay_column()
	var title := Label.new()
	title.text = "MISSION COMPLETE · PICK AN UPGRADE"
	title.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	title.add_theme_font_size_override("font_size", 22)
	box.add_child(title)
	_add_upgrade(box, "FIELD ARMOR  +25 MAX HEALTH", "armor")
	_add_upgrade(box, "QUICK TRIGGER  ·  FASTER FIRE", "trigger")
	_add_upgrade(box, "HOT ROUNDS  ·  MORE DAMAGE", "rounds")

func _add_upgrade(parent: VBoxContainer, title: String, effect: String) -> void:
	var button := Button.new()
	button.text = title
	button.custom_minimum_size.y = 45
	button.pressed.connect(func():
		player.apply_upgrade(effect)
		kills = 0
		active = true
		player.set_physics_process(true)
		overlay.visible = false
		_spawn_guards(4)
		_update_hud()
	)
	parent.add_child(button)

func _on_health_changed(current: int, maximum: int) -> void:
	health_label.text = "VITALITY  %d / %d" % [current, maximum]
	if current <= 0:
		active = false
		_show_retry()

func _show_retry() -> void:
	Input.mouse_mode = Input.MOUSE_MODE_VISIBLE
	player.set_physics_process(false)
	overlay.visible = true
	_clear_overlay()
	var box := _overlay_column()
	var title := Label.new()
	title.text = "SQUAD DOWN · CHECKPOINT SAVED"
	title.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	box.add_child(title)
	var retry := Button.new()
	retry.text = "RETRY MISSION"
	retry.pressed.connect(func():
		for enemy in get_tree().get_nodes_in_group("enemies"):
			enemy.queue_free()
		kills = 0
		boss_active = false
		player.restore_checkpoint()
		active = true
		overlay.visible = false
		_spawn_guards(2 if mission == MISSIONS.size() else 4)
	)
	box.add_child(retry)

func _show_victory() -> void:
	Input.mouse_mode = Input.MOUSE_MODE_VISIBLE
	overlay.visible = true
	_clear_overlay()
	var box := _overlay_column()
	var title := Label.new()
	title.text = "IRON VULTURE DEFEATED"
	title.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	title.add_theme_font_size_override("font_size", 28)
	box.add_child(title)
	var body := Label.new()
	body.text = "The frontier is free. Your campaign completion is saved locally."
	body.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	box.add_child(body)

func _update_hud() -> void:
	if is_instance_valid(hud_label):
		hud_label.text = "MISSION %d / %d   ·   %s   ·   HOSTILES %d" % [mission, MISSIONS.size(), MISSIONS[mission - 1], 2 if mission == MISSIONS.size() else 4]

func _clear_overlay() -> void:
	for child in overlay.get_children():
		child.queue_free()

func _overlay_column() -> VBoxContainer:
	var box := VBoxContainer.new()
	box.add_theme_constant_override("separation", 14)
	box.alignment = BoxContainer.ALIGNMENT_CENTER
	overlay.add_child(box)
	return box

func _add_reticle(root: Control) -> void:
	var reticle := Control.new()
	reticle.name = "AimReticle"
	reticle.set_anchors_and_offsets_preset(Control.PRESET_CENTER)
	reticle.position = Vector2(-13, -13)
	reticle.custom_minimum_size = Vector2(26, 26)
	for spec in [Vector4(12, 0, 2, 8), Vector4(12, 18, 2, 8), Vector4(0, 12, 8, 2), Vector4(18, 12, 8, 2)]:
		var tick := ColorRect.new()
		tick.position = Vector2(spec.x, spec.y)
		tick.size = Vector2(spec.z, spec.w)
		tick.color = Color(0.86, 0.94, 0.78, 0.9)
		reticle.add_child(tick)
	root.add_child(reticle)

func _build_vegetation_and_field_props() -> void:
	var rng := RandomNumberGenerator.new()
	rng.seed = 849223
	var leaf_material := StandardMaterial3D.new()
	leaf_material.albedo_color = Color(0.20, 0.34, 0.20)
	leaf_material.roughness = 0.94
	var stone_material := StandardMaterial3D.new()
	stone_material.albedo_color = Color(0.31, 0.34, 0.30)
	stone_material.roughness = 1.0
	for i in range(52):
		var x := rng.randf_range(-48, 48)
		var z := rng.randf_range(-46, 38)
		if absf(x) < 7.0 and z > -8.0 and z < 18.0:
			continue
		var shrub := Node3D.new()
		shrub.position = Vector3(x, 0, z)
		shrub.rotation.y = rng.randf_range(0, TAU)
		var cluster_count := rng.randi_range(2, 4)
		for j in range(cluster_count):
			var leaf := MeshInstance3D.new()
			var sphere := SphereMesh.new()
			sphere.radius = rng.randf_range(0.42, 0.72)
			sphere.height = sphere.radius * 1.55
			leaf.mesh = sphere
			leaf.material_override = leaf_material
			leaf.position = Vector3(rng.randf_range(-0.45, 0.45), sphere.radius * 0.48, rng.randf_range(-0.4, 0.4))
			shrub.add_child(leaf)
		add_child(shrub)
	for i in range(30):
		var rock := MeshInstance3D.new()
		var rock_mesh := SphereMesh.new()
		rock_mesh.radius = rng.randf_range(0.35, 0.95)
		rock_mesh.height = rock_mesh.radius * rng.randf_range(0.55, 1.2)
		rock.mesh = rock_mesh
		rock.material_override = stone_material
		rock.position = Vector3(rng.randf_range(-48, 48), rock_mesh.height * 0.32, rng.randf_range(-44, 34))
		rock.scale = Vector3(rng.randf_range(0.8, 1.45), 1.0, rng.randf_range(0.8, 1.4))
		add_child(rock)

func _build_landscape() -> void:
	var ground := StaticBody3D.new()
	ground.name = "Terrain"
	var mesh := MeshInstance3D.new()
	var plane := PlaneMesh.new()
	plane.size = Vector2(GROUND_SIZE, GROUND_SIZE)
	mesh.mesh = plane
	var material := StandardMaterial3D.new()
	var ground_palette: Array[Color] = [Color(0.20,0.29,0.19),Color(0.32,0.34,0.27),Color(0.16,0.24,0.21),Color(0.36,0.27,0.20),Color(0.28,0.34,0.32),Color(0.18,0.20,0.19)]
	material.albedo_color = ground_palette[mission - 1]
	material.roughness = 1.0
	mesh.material_override = material
	ground.add_child(mesh)
	var collision := CollisionShape3D.new()
	var shape := BoxShape3D.new()
	shape.size = Vector3(GROUND_SIZE, 0.2, GROUND_SIZE)
	collision.shape = shape
	collision.position.y = -0.1
	ground.add_child(collision)
	add_child(ground)

	# Layered ridgelines give the first greybox a clear sense of distance.
	for row in range(3):
		for i in range(12):
			var hill := MeshInstance3D.new()
			var cone := CylinderMesh.new()
			cone.top_radius = 0.0
			cone.bottom_radius = 11.0 + float((i * 7) % 9)
			cone.height = 20.0 + float((i * 13) % 18)
			hill.mesh = cone
			var m := StandardMaterial3D.new()
			m.albedo_color = [Color(0.28,0.37,0.35),Color(0.22,0.33,0.29),Color(0.19,0.29,0.23)][row]
			m.roughness = 1.0
			hill.material_override = m
			hill.position = Vector3(-95 + i * 18 + row * 7, cone.height * 0.5 - 4, -56 - row * 22)
			add_child(hill)

func _build_cover() -> void:
	var rng := RandomNumberGenerator.new()
	rng.seed = 74117
	for i in range(70):
		var x := rng.randf_range(-42, 42)
		var z := rng.randf_range(-44, 32)
		if absf(x) < 5.0 and z > -5.0 and z < 16.0:
			continue
		_add_tree(Vector3(x, 0, z), rng.randf_range(0.8, 1.4))
	for i in range(18):
		var wall := StaticBody3D.new()
		var box := MeshInstance3D.new()
		var block := BoxMesh.new()
		block.size = Vector3(rng.randf_range(1.5, 3.5), rng.randf_range(1.3, 2.8), 1.2)
		box.mesh = block
		var wall_material := StandardMaterial3D.new()
		wall_material.albedo_color = Color(0.38, 0.36, 0.28)
		wall_material.roughness = 0.92
		box.material_override = wall_material
		wall.add_child(box)
		var collider := CollisionShape3D.new()
		var wall_shape := BoxShape3D.new()
		wall_shape.size = block.size
		collider.shape = wall_shape
		wall.add_child(collider)
		wall.position = Vector3(rng.randf_range(-32,32), block.size.y * 0.5, rng.randf_range(-28, -8))
		wall.rotation.y = rng.randf_range(-0.25, 0.25)
		add_child(wall)

func _add_tree(at: Vector3, scale_factor: float) -> void:
	var tree_body := StaticBody3D.new()
	tree_body.position = at
	var trunk := MeshInstance3D.new()
	var trunk_mesh := CylinderMesh.new()
	trunk_mesh.top_radius = 0.18 * scale_factor
	trunk_mesh.bottom_radius = 0.3 * scale_factor
	trunk_mesh.height = 3.2 * scale_factor
	trunk.mesh = trunk_mesh
	var bark := StandardMaterial3D.new()
	bark.albedo_color = Color(0.29, 0.19, 0.12)
	trunk.material_override = bark
	trunk.position = Vector3(0, trunk_mesh.height * 0.5, 0)
	tree_body.add_child(trunk)
	var trunk_collider := CollisionShape3D.new()
	var trunk_shape := CylinderShape3D.new()
	trunk_shape.radius = 0.30 * scale_factor
	trunk_shape.height = trunk_mesh.height
	trunk_collider.shape = trunk_shape
	trunk_collider.position = trunk.position
	tree_body.add_child(trunk_collider)
	add_child(tree_body)
	var crown := MeshInstance3D.new()
	var crown_mesh := SphereMesh.new()
	crown_mesh.radius = 1.55 * scale_factor
	crown_mesh.height = 2.5 * scale_factor
	crown.mesh = crown_mesh
	var leaves := StandardMaterial3D.new()
	leaves.albedo_color = Color(0.14, 0.30, 0.18)
	leaves.roughness = 0.9
	crown.material_override = leaves
	crown.position = at + Vector3(0, 3.0 * scale_factor, 0)
	add_child(crown)
