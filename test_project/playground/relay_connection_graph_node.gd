extends GraphNode
class_name RelayConnectionGraphNode

@export var _relay_connection: NostrRelayConnection
@onready var input = $UrlLineEdit
@onready var connect_button = $ConnectButton

var connected = false

func _ready() -> void:
	_relay_connection.connected.connect(_on_relay_connected)
	_relay_connection.disconnected.connect(_on_relay_disconnected)
	
func _on_url_input_submitted(new_text: String) -> void:
	_relay_connection.set_url(new_text)
	_relay_connection.relay_connect()
	
func _on_relay_connected(_url: String) -> void:
	print("CONNECTED")
	connected = true
	connect_button.text = "Online"
	connect_button.self_modulate = Color(0.0, 1.0, 0.0, 1.0)

func _on_relay_disconnected(_url: String) -> void:
	print("DISCONNECTED")
	connected = false
	connect_button.text = "Offline"
	connect_button.self_modulate = Color(1.0, 1.0, 1.0, 1.0)
	
func _on_connect_button_toggled(toggled_on: bool) -> void:
	if toggled_on:
		_relay_connection.set_url(input.text, true)
	else:
		_relay_connection.relay_disconnect()


func _on_slot_updated(slot_index: int) -> void:
	print("Relay Connection Node slot updated: ", slot_index)
	
func subscribe(sub: String) -> void:
	print(sub)
	_relay_connection.subscribe(sub)
