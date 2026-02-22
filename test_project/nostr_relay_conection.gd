extends Node
class_name NostrRelayConnection

signal connected(url: String)
signal disconnected(url: String)
signal received(url: String, msg: Array)

var _url: String
var _socket: WebSocketPeer
var _connected = false

func set_url(url: String, auto_connect: bool = false) -> void:
	if not _is_valid_websocket_url(url):
		print_rich("[color=yellow][b][ NOSTR: WARNING ][/b] Not valid url. Should start with wss:// or ws://[/color]")
		
	_url = url
	relay_disconnect()
	
	if auto_connect:
		relay_connect()

func relay_disconnect() -> void:
	if _socket == null:
		return
		
	_socket.close()
	await get_tree().create_timer(1).timeout
	_socket = null

func relay_connect() -> void:
	if _url == "":
		print_rich("[color=yellow][b][ NOSTR: WARNING ][/b] Please set url first. [code]set_url(url: String, auto_connect: bool)[/code][/color]")
		return
		
	_socket = WebSocketPeer.new()
	
	var err = _socket.connect_to_url(_url)
	if err != OK:
		print_rich("[color=red][b][ NOSTR: ERROR ][/b] Problem connecting[/color]")

func subscribe(sub: String) -> void:
	if _socket == null || _socket.get_ready_state() != WebSocketPeer.STATE_OPEN:
		print_rich("[color=yellow][b][ NOSTR: WARNING ][/b] Relay not connected[/color]")
		return
	
	_socket.send_text(sub)

func is_relay_connected() -> bool:
	return _connected

func _process(_delta: float) -> void:
	if _socket == null:
		return
		
	_socket.poll()
	
	var state = _socket.get_ready_state()
	
	match state:
		WebSocketPeer.STATE_OPEN:
			if _connected == false:
				_connected = true
				connected.emit(_url)
			while _socket.get_available_packet_count():
				var packet = _socket.get_packet()
				if _socket.was_string_packet():
					var dict = JSON.parse_string(packet.get_string_from_utf8())
					#print(dict)
					received.emit(_url, dict)
		WebSocketPeer.STATE_CLOSED:
			_connected = false
			disconnected.emit(_url)
			_socket = null ## TODO: Should we do this? This means you ahve to set url again.

func _is_valid_websocket_url(url: String) -> bool:
	var regex = RegEx.new()
	# Matches: ws:// or wss://, followed by domain/IP, optional :port, optional /path
	regex.compile("^wss?://[a-zA-Z0-9.-]+(:\\d+)?(/.*)?$")
	return regex.search(url) != null
