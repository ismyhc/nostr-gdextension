#pragma once

#include "godot_cpp/classes/ref_counted.hpp"
#include "godot_cpp/variant/dictionary.hpp"

extern "C" {
	#include <secp256k1.h>
	#include <secp256k1_extrakeys.h>
	#include <secp256k1_schnorrsig.h>
}

using namespace godot;

class Nostr : public RefCounted {
	GDCLASS(Nostr, RefCounted)

protected:
	static void _bind_methods();
	static secp256k1_context* get_randomized_context();

private:
	static Dictionary generate_key();
	static Dictionary key_from_seckey(const String& seckey_hex);
	static String sign(const String& msg, const String& seckey_hex);
};
