extends Node2D

@onready var relay_connection_graph_node = preload("res://playground/relay_connection_graph_node.tscn")
@onready var subscription_graph_node = preload("res://playground/subscription_node.tscn")

@onready var n := Nostr.new()
@onready var graph_edit = $UI/GraphEdit

func _ready() -> void:
	pass
	
func _input(event):
	if event is InputEventKey and event.pressed and not event.echo:
		if event.keycode == KEY_F1:
			var i = relay_connection_graph_node.instantiate()
			i.name = "relay_connection_" + str(Time.get_unix_time_from_system())
			i.owner = get_tree().edited_scene_root
			var pos = get_global_mouse_position()
			i.position_offset = pos
			graph_edit.add_child(i)
		if event.keycode == KEY_F2:
			var i = subscription_graph_node.instantiate()
			i.name = "subscription_" + str(Time.get_unix_time_from_system())
			i.owner = get_tree().edited_scene_root
			var pos = get_global_mouse_position()
			i.position_offset = pos
			graph_edit.add_child(i)

func test_plugin_functionality() -> void:
	pass
	#var kp = Nostr.create_new_keypair()
	#print(kp["seckey"])
	#print(kp["pubkey"])

	#n.keypair_pow_done.connect(func(res): 
		#$RichTextLabel.text = JSON.stringify(res)
	#)
	#n.request_create_new_keypair_pow(16)
	#n.request_create_new_keypair_pow(20)
	
	#print("FUCK YOU")

	#print("FUCK")
	
	#var kp: Dictionary = Nostr.create_new_keypair()
	#
	#var event = {
		#"pubkey": kp["pubkey"],
		#"created_at": int(Time.get_unix_time_from_system()),
		#"kind": 1,
		#"tags": [
			#["p", kp["pubkey"]]
		#],
		#"content": "Hello from Godot"
	#}
	#
	#var signed_event = Nostr.sign_event(event, kp["seckey"])
	#
	#print(signed_event)

	#print("Hex Private Key: " + kd["seckey"])
	#print("Hex Public Key: " + kd["pubkey"])
	#
	#print("Bech32 Private Key: " + kd["bech32_seckey"])
	#print("Bech32 Public Key: " + kd["bech32_pubkey"])
	#
	#print(Nostr.hex_to_npub(kd["pubkey"]))
	
	#var nk = Nostr.keypair_from_seckey(kd["seckey"])
	#
	#print(nk["seckey"])
	#print(nk["pubkey"])

func _on_node_connection_request(from_node: StringName, from_port: int, to_node: StringName, to_port: int) -> void:
	print("CONNECT FROM: ", from_node)
	print("CONNECT TO: ", to_node)
	graph_edit.connect_node(from_node, from_port, to_node, to_port)
	
	if from_node.contains("subscription_") and to_node.contains("relay_connection_"):
		var sub = graph_edit.get_node(NodePath(from_node)) as SubscriptionNode
		var relay = graph_edit.get_node(NodePath(to_node)) as RelayConnectionGraphNode
		relay.subscribe(sub.get_subscription())

func _on_node_disconnection_request(from_node: StringName, from_port: int, to_node: StringName, to_port: int) -> void:
	print("DISCONNECT FROM: ", from_node)
	print("DISCONNECT TO: ", to_node)
	graph_edit.disconnect_node(from_node, from_port, to_node, to_port)
