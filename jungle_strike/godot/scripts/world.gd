extends Node3D

const PLAYER_SCENE := preload("res://scenes/player.tscn")
const ENEMY_SCENE := preload("res://scenes/enemy.tscn")
const FLOOR_COUNT := 50
const GROUND_SIZE := 180.0
const FLOOR_NAMES := ["SECURITY INTAKE", "POWER CORE", "RESEARCH WING", "CONTAINMENT", "ARCHIVE VAULT", "DRONE FOUNDRY", "EXECUTIVE LEVEL", "NEURAL LAB", "REACTOR RING", "BLACKOUT TOWER"]
const RADIO_GUIDANCE := ["Stay low. The drones are tracking heat signatures.", "I am Dr. Mira Sen. Follow the emergency strobes to the next lift.", "The security team is not responding to my override.", "I found your Kinetic Suit file. You were here before, weren't you?", "That is not a maintenance signal. Something is answering us."]
const STORY_TWISTS := ["I did not trigger the lockdown. Someone used my credentials.", "The AI was ordered to protect the research—not the people.", "The guards were told the facility had already been evacuated.", "Your suit was the first neural interface we tested. The memory gaps are deliberate.", "The tower is learning from every fight. It is adapting to you.", "I found a second command signature. It matches your old field ID.", "The blackout was staged to hide the transfer of a living subject.", "The AI is not killing at random. It is removing everyone who knows the truth.", "The person who signed the kill order is still inside the tower.", "That signature is mine. I created the AI—and gave it a conscience.", "The subject in the core is not a weapon. It is my daughter.", "You were sent to erase the evidence. Your handler never planned an extraction.", "The guards are clones grown from the original security team.", "The blackout is also keeping something below us contained.", "The AI has been using the tower's power to keep the city grid alive.", "The command logs show your old unit reached the core before you did.", "I have been guiding you from a dead channel. I am not in the control room.", "The voice you hear is a recording. I died on the night of the lockdown.", "The tower has been rebuilding itself around your route.", "Your suit is the only key that can shut the core down.", "If you kill the AI, the city loses power. There is another way.", "The subject is awake. She has been speaking through the security network.", "Your memories were copied into the tower during the first experiment.", "I am not Mira. I am the part of her that the AI could not delete.", "At the top, choose: destroy the core, or trust the voice inside it."]
const FLOOR_COUNT_PER_CHAPTER := 5

var player: JunglePlayer
var mission := 1
var kills := 0
var unlocked := 1
var story_label: Label
var radio_label: Label
var hud_label: Label
var floor_kills := 0
var radio_generation := 0
var health_label: Label
var overlay: PanelContainer
var active := false
var boss_active := false
var save_path := "user://jungle_campaign.cfg"

func _ready() -> void:
	_build_input_map()
	_load_progress()
	_build_tower_interior()
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
		unlocked = clampi(int(data.get_value("campaign", "unlocked", 1)), 1, FLOOR_COUNT)
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
	radio_label = Label.new()
	radio_label.position = Vector2(24, 92)
	radio_label.custom_minimum_size = Vector2(minf(640.0, get_viewport().get_visible_rect().size.x * 0.62), 64)
	radio_label.autowrap_mode = TextServer.AUTOWRAP_WORD_SMART
	radio_label.add_theme_font_size_override("font_size", 18)
	radio_label.add_theme_color_override("font_color", Color(0.68, 0.88, 1.0))
	root.add_child(radio_label)
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
	title.text = "THE BLACKOUT TOWER"
	title.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	title.add_theme_font_size_override("font_size", 28)
	box.add_child(title)
	story_label = Label.new()
story_label.text = "A 50-floor autonomous research tower has sealed itself. Security drones and armored guards are hunting everyone inside. You are an ex-agent in an experimental Kinetic Suit. Fight upward, follow Dr. Mira Sen’s radio calls, and uncover who ordered the blackout. Your floor checkpoint saves locally."
story_label.autowrap_mode = TextServer.AUTOWRAP_WORD_SMART
	story_label.custom_minimum_size.x = minf(430.0, get_viewport().get_visible_rect().size.x - 70.0)
	box.add_child(story_label)
	var mission_label := Label.new()
	mission_label.text = "CONTINUE · FLOOR %02d / %02d · %s" % [mission, FLOOR_COUNT, _floor_name(mission)]
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
	_begin_floor()

func _begin_floor() -> void:
	active = true
	floor_kills = 0
	boss_active = false
	player.restore_checkpoint()
	var chapter := int((mission - 1) / FLOOR_COUNT_PER_CHAPTER)
	var spawn_count := 2 + mini(chapter, 3)
	if mission % 10 == 0:
		spawn_count = 2 + mini(chapter, 3)
	_spawn_guards(spawn_count)
	_update_hud()
	var guidance := RADIO_GUIDANCE[(mission - 1) % RADIO_GUIDANCE.size()]
	_radio_transmission("DR. MIRA", "Floor %02d: %s" % [mission, guidance])

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
	enemy.position = Vector3(0, 0.05, -22)
	add_child(enemy)
	enemy.setup(player, true)
	enemy.defeated.connect(_on_boss_defeated)
	_update_hud()
	_radio_transmission("TOWER AI · HELIX", "Containment response active. Kinetic subject will be terminated.")

func _on_enemy_defeated() -> void:
	kills += 1
	floor_kills += 1
	var required_kills := 2 + mini(int((mission - 1) / FLOOR_COUNT_PER_CHAPTER), 3)
	if floor_kills >= required_kills and mission % 10 == 0 and not boss_active:
		_spawn_boss()
	elif floor_kills >= required_kills and mission % 10 != 0:
		_complete_floor()
	_update_hud()

func _complete_floor() -> void:
	active = false
	player.set_physics_process(false)
	unlocked = mini(FLOOR_COUNT + 1, mission + 1)
	_save_progress()
	if mission % 2 == 0:
		var twist_index := int(mission / 2) - 1
		_radio_transmission("DR. MIRA · ENCRYPTED", STORY_TWISTS[twist_index])
	if mission >= FLOOR_COUNT:
		_show_victory()
	else:
		mission += 1
		_save_progress()
		if mission % 5 == 0:
			_show_upgrade()
		else:
			_show_floor_clear()

func _on_boss_defeated() -> void:
	player.set_boss_camera(false)
	_complete_floor()

func _show_floor_clear() -> void:
	Input.mouse_mode = Input.MOUSE_MODE_VISIBLE
	overlay.visible = true
	_clear_overlay()
	var box := _overlay_column()
	var title := Label.new()
	title.text = "FLOOR %02d SECURED" % (mission - 1)
	title.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	title.add_theme_font_size_override("font_size", 24)
	box.add_child(title)
	var body := Label.new()
	body.text = "Lift power restored. Dr. Mira is waiting on the next floor."
	body.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	box.add_child(body)
	var next_button := Button.new()
	next_button.text = "ASCEND TO FLOOR %02d" % mission
	next_button.custom_minimum_size.y = 50
	next_button.pressed.connect(func():
		overlay.visible = false
		if not OS.has_feature("mobile"):
			Input.mouse_mode = Input.MOUSE_MODE_CAPTURED
		_begin_floor()
	)
	box.add_child(next_button)

func _radio_transmission(speaker: String, message: String) -> void:
	if not is_instance_valid(radio_label):
		return
	radio_generation += 1
	var generation := radio_generation
	radio_label.text = "◉  %s  /  %s" % [speaker, message]
	radio_label.visible = true
	var timer := get_tree().create_timer(6.5)
	timer.timeout.connect(func():
		if is_instance_valid(radio_label) and generation == radio_generation:
			radio_label.text = ""
	)

func _floor_name(floor_number: int) -> String:
	var chapter := mini(int((floor_number - 1) / FLOOR_COUNT_PER_CHAPTER), FLOOR_NAMES.size() - 1)
	return FLOOR_NAMES[chapter]

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
		overlay.visible = false
		if not OS.has_feature("mobile"):
			Input.mouse_mode = Input.MOUSE_MODE_CAPTURED
		_begin_floor()
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
		overlay.visible = false
		_begin_floor()
	)
	box.add_child(retry)

func _show_victory() -> void:
	Input.mouse_mode = Input.MOUSE_MODE_VISIBLE
	overlay.visible = true
	_clear_overlay()
	var box := _overlay_column()
	var title := Label.new()
	title.text = "THE BLACKOUT TOWER · CORE REACHED"
	title.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	title.add_theme_font_size_override("font_size", 28)
	box.add_child(title)
	var body := Label.new()
	body.text = "HELIX is offline. The 50-floor campaign and your ending are saved on this device."
	body.horizontal_alignment = HORIZONTAL_ALIGNMENT_CENTER
	box.add_child(body)

func _update_hud() -> void:
	if is_instance_valid(hud_label):
		var objective := "ELIMINATE THE SECURITY DETAIL"
		if mission % 10 == 0:
			objective = "CONTAINMENT UNIT · FLOOR BOSS"
		hud_label.text = "BLACKOUT TOWER  ·  FLOOR %02d / %02d  ·  %s" % [mission, FLOOR_COUNT, _floor_name(mission)]
		if active:
			hud_label.text += "\nOBJECTIVE  %s" % objective

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

func _build_tower_interior() -> void:
	var concrete := _facility_material(Color(0.13, 0.17, 0.21), 0.88)
	var dark_metal := _facility_material(Color(0.055, 0.075, 0.095), 0.62)
	var panel_metal := _facility_material(Color(0.22, 0.27, 0.29), 0.72)
	var cyan_light := _facility_material(Color(0.06, 0.66, 0.82), 0.32, Color(0.03, 0.42, 0.78))
	var warning_light := _facility_material(Color(0.8, 0.18, 0.08), 0.38, Color(0.7, 0.035, 0.01))
	_add_facility_box("FloorSlab", Vector3(0, -0.38, 0), Vector3(54, 0.76, 54), concrete, true)
	_add_facility_box("CeilingRim", Vector3(0, 7.2, -1), Vector3(54, 0.45, 52), dark_metal, false)
	_add_facility_box("NorthWall", Vector3(0, 3.4, -26), Vector3(54, 7.2, 0.8), dark_metal, true)
	_add_facility_box("SouthWall", Vector3(0, 3.4, 26), Vector3(54, 7.2, 0.8), dark_metal, true)
	_add_facility_box("EastWall", Vector3(26, 3.4, 0), Vector3(0.8, 7.2, 52), dark_metal, true)
	_add_facility_box("WestWall", Vector3(-26, 3.4, 0), Vector3(0.8, 7.2, 52), dark_metal, true)
	for x in [-24.0, -18.0, -12.0, -6.0, 0.0, 6.0, 12.0, 18.0, 24.0]:
		_add_facility_box("CeilingLight", Vector3(x, 6.94, 0), Vector3(0.12, 0.05, 22), cyan_light, false)
	for x in [-22.0, 22.0]:
		for z in [-19.0, -7.0, 7.0, 19.0]:
			_add_facility_box("SupportColumn", Vector3(x, 2.0, z), Vector3(1.6, 4.7, 1.6), panel_metal, true)
			_add_facility_box("ColumnLight", Vector3(x, 3.2, z - 0.82), Vector3(0.10, 1.3, 0.035), warning_light, false)
	for z in [-23.0, -16.0, 16.0, 23.0]:
		_add_facility_box("WallPanel", Vector3(0, 3.8, z), Vector3(8.0, 2.0, 0.16), panel_metal, false)
		_add_facility_box("AccessStrip", Vector3(0, 4.95, z - 0.12), Vector3(2.0, 0.06, 0.08), warning_light, false)
	# Modular lab consoles and heavy cover make the combat space read like a real facility.
	for pos in [Vector3(-10, 0.75, -8), Vector3(10, 0.75, -8), Vector3(-10, 0.75, 8), Vector3(10, 0.75, 8)]:
		_add_facility_box("LabConsole", pos, Vector3(3.2, 1.5, 1.0), dark_metal, true)
		_add_facility_box("ConsoleDisplay", pos + Vector3(0, 0.32, -0.53), Vector3(1.7, 0.38, 0.055), cyan_light, false)
	_add_facility_box("LiftDoor", Vector3(0, 2.2, -25.35), Vector3(6.0, 4.4, 0.12), panel_metal, false)
	_add_facility_box("LiftSignal", Vector3(0, 4.6, -25.15), Vector3(1.4, 0.12, 0.08), warning_light, false)

func _facility_material(color: Color, roughness: float, emission: Color = Color.BLACK) -> StandardMaterial3D:
	var material := StandardMaterial3D.new()
	material.albedo_color = color
	material.roughness = roughness
	if emission != Color.BLACK:
		material.emission_enabled = true
		material.emission = emission
		material.emission_energy_multiplier = 2.2
	return material

func _add_facility_box(node_name: String, at: Vector3, dimensions: Vector3, material: Material, collidable: bool) -> void:
	var root: Node3D = StaticBody3D.new() if collidable else Node3D.new()
	root.name = node_name
	root.position = at
	var mesh_instance := MeshInstance3D.new()
	var box_mesh := BoxMesh.new()
	box_mesh.size = dimensions
	mesh_instance.mesh = box_mesh
	mesh_instance.material_override = material
	root.add_child(mesh_instance)
	if collidable:
		var collision := CollisionShape3D.new()
		var box_shape := BoxShape3D.new()
		box_shape.size = dimensions
		collision.shape = box_shape
		root.add_child(collision)
	add_child(root)

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
