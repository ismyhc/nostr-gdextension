extends Node2D

func _ready() -> void:
	test_plugin_functionality()

func test_plugin_functionality()->void:
	
	var kp = Nostr.create_new_keypair()
	print(kp["seckey"])
	print(kp["pubkey"])
	#var n = Nostr.new()
	#n.keypair_pow_done.connect(func(res): print(res))
	#n.request_create_new_keypair_pow(1)
	#print("FUCK")
	
	#var kp: Dictionary = Nostr.create_new_keypair()
	#
	#var event = {
		#"pubkey": kp["pubkey"],
		#"created_at": int(Time.get_unix_time_from_system()),
		#"kind": 1,
		#"tags": [
			##"p", kp["pubkey"]
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
