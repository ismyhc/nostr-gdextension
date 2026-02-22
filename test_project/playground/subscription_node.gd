extends GraphNode
class_name SubscriptionNode

signal node_enabled

var sub_id = randi() % 10000

func _ready() -> void:
	pass

func _on_slot_updated(slot_index: int) -> void:
	print("Subscription Node slot updated: ", slot_index)

func _on_enable_button_toggled(toggled_on: bool) -> void:
	print(get_subscription())
	node_enabled.emit(name, toggled_on, get_subscription())

func get_subscription() -> String:
	var id_strings = $VBoxContainer/IdsLineEdit.text.split(",")
	var ids = []
	for id in id_strings:
		var v = id.strip_edges()
		if v != "":
			ids.append(id.strip_edges())
		
	var author_strings = $VBoxContainer/AuthorsLineEdit.text.split(",")
	var authors = []
	for author in author_strings:
		var v =  author.strip_edges()
		if v != "":
			authors.append(author.strip_edges())
		
	var kind_strings = $VBoxContainer/KindsLineEdit.text.split(",")
	var kinds = []
	for kind in kind_strings:
		var v = kind.strip_edges().to_int()
		kinds.append(v)
		
	var limit = $VBoxContainer/LimitLineEdit.text.to_int()
	var dict: Dictionary = {}
	if len(ids) > 0:
		dict["ids"] = ids
	if len(authors) > 0:
		dict["authors"] = authors
	if len(kinds) > 0:
		dict["kinds"] = kinds
	dict["limit"] = limit

	return '["REQ", "%s", %s]' % [sub_id, JSON.stringify(dict)]
