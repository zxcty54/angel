extends Control

signal move_changed(value: Vector2)
signal fire_changed(pressed: bool)
signal jump_pressed
signal dodge_pressed
signal look_changed(delta: Vector2)

var _stick_finger := -1
var _fire_finger := -1
var _look_finger := -1
var _stick_center := Vector2.ZERO
var _stick_value := Vector2.ZERO
var _fire_down := false

func _ready() -> void:
	set_anchors_and_offsets_preset(Control.PRESET_FULL_RECT)
	mouse_filter = Control.MOUSE_FILTER_IGNORE
	set_process(true)
	get_viewport().size_changed.connect(queue_redraw)

func _process(_delta: float) -> void:
	queue_redraw()

func _input(event: InputEvent) -> void:
	var screen := get_viewport().get_visible_rect().size
	if event is InputEventScreenTouch:
		if event.pressed:
			if event.position.x < screen.x * 0.52 and event.position.y > screen.y * 0.42 and _stick_finger == -1:
				_stick_finger = event.index
				_stick_center = Vector2(screen.x * 0.22, screen.y * 0.80)
				_update_stick(event.position)
			elif event.position.x > screen.x * 0.52:
				if not _handle_button_down(event.position, screen, event.index):
					_look_finger = event.index
		else:
			if event.index == _stick_finger:
				_stick_finger = -1
				_stick_value = Vector2.ZERO
				move_changed.emit(_stick_value)
			if event.index == _fire_finger:
				_fire_finger = -1
				_fire_down = false
				fire_changed.emit(false)
			if event.index == _look_finger:
				_look_finger = -1
	elif event is InputEventScreenDrag:
		if event.index == _stick_finger:
			_update_stick(event.position)
		elif event.index == _look_finger:
			look_changed.emit(event.relative)

func _handle_button_down(pos: Vector2, size: Vector2, finger: int) -> bool:
	var fire_center := Vector2(size.x * 0.84, size.y * 0.81)
	var jump_center := Vector2(size.x * 0.70, size.y * 0.86)
	var dodge_center := Vector2(size.x * 0.70, size.y * 0.68)
	if pos.distance_to(fire_center) < size.x * 0.14 and _fire_finger == -1:
		_fire_finger = finger
		_fire_down = true
		fire_changed.emit(true)
		return true
	elif pos.distance_to(jump_center) < size.x * 0.13:
		jump_pressed.emit()
		return true
	elif pos.distance_to(dodge_center) < size.x * 0.13:
		dodge_pressed.emit()
		return true
	return false

func _update_stick(pos: Vector2) -> void:
	var size := get_viewport().get_visible_rect().size
	var radius := minf(72.0, size.x * 0.19)
	_stick_value = ((pos - _stick_center) / radius).limit_length(1.0)
	move_changed.emit(_stick_value)

func _draw() -> void:
	var size := get_viewport().get_visible_rect().size
	var base := Vector2(size.x * 0.22, size.y * 0.80)
	var stick_radius := minf(72.0, size.x * 0.19)
	var knob := base + _stick_value * stick_radius
	_draw_button(base, stick_radius, Color(0.05, 0.10, 0.12, 0.34), "MOVE")
	_draw_button(knob, stick_radius * 0.40, Color(0.52, 0.86, 0.77, 0.55), "")
	_draw_button(Vector2(size.x * 0.84, size.y * 0.81), size.x * 0.14, Color(0.83, 0.24, 0.16, 0.72 if _fire_down else 0.48), "FIRE")
	_draw_button(Vector2(size.x * 0.70, size.y * 0.86), size.x * 0.12, Color(0.18, 0.45, 0.73, 0.58), "JUMP")
	_draw_button(Vector2(size.x * 0.70, size.y * 0.68), size.x * 0.12, Color(0.20, 0.67, 0.56, 0.58), "DODGE")

func _draw_button(center: Vector2, radius: float, color: Color, label: String) -> void:
	draw_circle(center, radius, color)
	draw_arc(center, radius, 0, TAU, 48, Color(0.88, 0.94, 0.87, 0.58), 2.0, true)
	if label != "":
		var font := ThemeDB.fallback_font
		var font_size := 15
		var width := font.get_string_size(label, HORIZONTAL_ALIGNMENT_LEFT, -1, font_size).x
		draw_string(font, center + Vector2(-width * 0.5, font_size * 0.35), label, HORIZONTAL_ALIGNMENT_LEFT, -1, font_size, Color.WHITE)
