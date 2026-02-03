extends Node2D

func _ready() -> void:
	test_plugin_functionality()

func test_plugin_functionality()->void:
	var kd = Nostr.generate_key()
	
	print(kd["seckey"])
	print(kd["pubkey"])
	
	var nk = Nostr.key_from_seckey(kd["seckey"])
	
	print(nk["seckey"])
	print(nk["pubkey"])
