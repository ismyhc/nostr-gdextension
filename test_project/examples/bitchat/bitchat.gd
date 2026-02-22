extends Control

@onready var relay_connection = NostrRelayConnection.new()
@onready var messages_scroll_container: ScrollContainer = $HBoxContainer/MessageContainer/MessagesScrollContainer
@onready var messages_vbox_container: VBoxContainer = $HBoxContainer/MessageContainer/MessagesScrollContainer/VBoxContainer

const SHOULD_SCROLL_DELTA = 800
const MAX_MESSAGES: int = 30

func _ready() -> void:
	add_child(relay_connection)
	relay_connection.set_url("wss://nos.lol")
	relay_connection.connected.connect(_on_connected)
	relay_connection.received.connect(_on_received)
	relay_connection.relay_connect()
	
func get_subscription() -> String:
	var dict = {
		"kinds": [1],
		"limit": int(25)
	}
	return '["REQ", "test", %s]' % [JSON.stringify(dict)]

func _on_connected(url: String) -> void:
	print("Connected to: " + url)
	relay_connection.subscribe(get_subscription())

func _on_received(_url: String, msg: Array) -> void:
	#print(msg)
	if msg.is_empty():
		return
	var type = msg[0] as String
	match type:
		"EVENT":
			var event = msg[2] as Dictionary
			add_message(event["content"] as String)

func scroll_to_bottom():
	var scroll_v = messages_scroll_container.get_v_scroll_bar()
	var max_value = scroll_v.max_value
	var delta = max_value - scroll_v.value
	
	if delta > SHOULD_SCROLL_DELTA:
		return
	
	# Wait for the next process frame to ensure the UI is updated and max_value is correct
	await get_tree().process_frame
	# Set the vertical scroll value to the maximum possible value
	messages_scroll_container.scroll_vertical = int(messages_scroll_container.get_v_scroll_bar().max_value)

func add_message(text: String) -> void:
	var l = RichTextLabel.new()
	l.selection_enabled = true
	l.fit_content = true
	l.autowrap_mode = TextServer.AUTOWRAP_WORD
	l.text = text
	messages_vbox_container.add_child(l)
	_prune_oldest()
	call_deferred("scroll_to_bottom")

func _prune_oldest() -> void:
	var overflow := messages_vbox_container.get_child_count() - MAX_MESSAGES
	if overflow <= 0:
		return
		
	# Remove the oldest (top) messages
	for i in overflow:
		var child := messages_vbox_container.get_child(0)
		child.queue_free()
