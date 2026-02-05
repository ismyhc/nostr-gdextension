#include "nostr.hpp"
#include "godot_cpp/core/class_db.hpp"
#include "godot_cpp/core/object.hpp"
#include "godot_cpp/variant/array.hpp"
#include "godot_cpp/variant/dictionary.hpp"
#include "godot_cpp/variant/packed_byte_array.hpp"
#include "godot_cpp/variant/string.hpp"
#include <godot_cpp/classes/json.hpp>
#include <cassert>
#include <cstring>

#include <godot_cpp/classes/crypto.hpp>
#include <godot_cpp/classes/worker_thread_pool.hpp>
#include <godot_cpp/variant/utility_functions.hpp>

//#pragma once

using namespace godot;

void Nostr::request_create_new_keypair_pow(int min_leading_zero_bits) {
    WorkerThreadPool::get_singleton()->add_task(
        Callable(this, "_pow_task").bind(min_leading_zero_bits),
        true
    );
}

void Nostr::_pow_task(int min_leading_zero_bits) {
	UtilityFunctions::print("Nostr: Starting Keypair POW task");
    //Dictionary result = create_new_keypair();//create_new_keypair_pow(min_leading_zero_bits);
	Dictionary result = Dictionary();
	result["Hello"] = "World";
    call_deferred("_pow_task_done", result);
}

void Nostr::_pow_task_done(const Dictionary& result) {
	UtilityFunctions::print("Nostr: Keypair POW task done");
    emit_signal("keypair_pow_done", result);
}

int Nostr::count_leading_zero_bits(const uint8_t* data, size_t data_len) {
	int count = 0;
	for (size_t i = 0; i < data_len; ++i) {
		uint8_t byte = data[i];
		for (int bit = 7; bit >= 0; --bit) {
			if ((byte >> bit) & 1) {
				return count;
			}
			count++;
		}
	}
	return count;
}

// Create a new keypair with number of leading zero bits in the pubkey
Dictionary Nostr::create_new_keypair_pow(int min_leading_zero_bits) {
	Dictionary retval;

	secp256k1_xonly_pubkey pubkey;
	secp256k1_keypair keypair;

	secp256k1_context *ctx = get_randomized_context();

	Ref<Crypto> crypto;
	crypto.instantiate();

	while (true) {
		PackedByteArray seckey = crypto->generate_random_bytes(32);
		int kpr = secp256k1_keypair_create(ctx, &keypair, seckey.ptr());
		assert(kpr == 1);

		int pubkey_create_r = secp256k1_keypair_xonly_pub(ctx, &pubkey, nullptr, &keypair);
		assert(pubkey_create_r == 1);

		unsigned char serialized_pubkey[32];
		int pubkey_serialize_r = secp256k1_xonly_pubkey_serialize(ctx, serialized_pubkey, &pubkey);
		assert(pubkey_serialize_r == 1);

		int leading_zero_bits = count_leading_zero_bits(serialized_pubkey, 32);
		if (leading_zero_bits >= min_leading_zero_bits) {
			// Write seckey
			retval["seckey"] = PackedByteArray(seckey).hex_encode();

			PackedByteArray pubkey_bytes;
			pubkey_bytes.resize(32);
			for (int i = 0; i < 32; ++i) {
				pubkey_bytes.set(i, serialized_pubkey[i]);
			}
			// Write pubkey
			retval["pubkey"] = pubkey_bytes.hex_encode();
			break;
		}
	}

	// Clean up
	secp256k1_context_destroy(ctx);

	return retval;
}

Dictionary Nostr::create_new_keypair() {
	Dictionary retval;

	secp256k1_xonly_pubkey pubkey;
	secp256k1_keypair keypair;
	secp256k1_context *ctx = get_randomized_context();

	unsigned char seckey[32];
	if (!secure_random_bytes(seckey, sizeof(seckey))) {
		print_line("Failed to generate secure random seckey");
		secp256k1_context_destroy(ctx);
		return Dictionary();
	}

	int kpr = secp256k1_keypair_create(ctx, &keypair, seckey);
	assert(kpr == 1);

	int pubkey_create_r = secp256k1_keypair_xonly_pub(ctx, &pubkey, nullptr, &keypair);
	assert(pubkey_create_r == 1);

	unsigned char serialized_pubkey[32];
	int pubkey_serialize_r = secp256k1_xonly_pubkey_serialize(ctx, serialized_pubkey, &pubkey);
	assert(pubkey_serialize_r == 1);

	// hex encode seckey
	String seckey_hex;
	{
		char seckey_hex_buf[65];
		size_t seckey_hex_len = bytes_to_hex(seckey_hex_buf, sizeof(seckey_hex_buf), seckey, 32);
		seckey_hex = String::utf8(seckey_hex_buf, (int)seckey_hex_len);
	}

	retval["seckey"] = seckey_hex;

	// hex encode pubkey
	String pubkey_hex;
	{
		char pubkey_hex_buf[65];
		size_t pubkey_hex_len = bytes_to_hex(pubkey_hex_buf, sizeof(pubkey_hex_buf), serialized_pubkey, 32);
		pubkey_hex = String::utf8(pubkey_hex_buf, (int)pubkey_hex_len);
	}

	// Write pubkey
	retval["pubkey"] = pubkey_hex;

	// // Encode seckey to bech32
	// char bech32_seckey[128];
	// CharString seckey_hex_cs = seckey_hex.utf8();
	// if (bech32_encode_hex("nsec", seckey_hex_cs.get_data(), bech32_seckey, sizeof(bech32_seckey))) {
	// 	retval["bech32_seckey"] = String(bech32_seckey);
	// } else {
	// 	retval["bech32_seckey"] = String();
	// }

	// // Encode pubkey to bech32
	// char bech32_pubkey[128];
	// String pubkey_hex = pubkey_bytes.hex_encode();
	// CharString pubkey_hex_cs = pubkey_hex.utf8();
	// if (bech32_encode_hex("npub", pubkey_hex_cs.get_data(), bech32_pubkey, sizeof(bech32_pubkey))) {
	// 	retval["bech32_pubkey"] = String(bech32_pubkey);
	// } else {
	// 	retval["bech32_pubkey"] = String();
	// }

	// Clean up
	secp256k1_context_destroy(ctx);

	return retval;
}

Dictionary Nostr::keypair_from_seckey(const String& seckey_hex) {
	Dictionary retval;
	retval["seckey"] = seckey_hex;

	secp256k1_xonly_pubkey pubkey;
	secp256k1_keypair keypair;

	secp256k1_context *ctx = get_randomized_context();

	// Decode seckey_hex to bytes
	PackedByteArray seckey_bytes = seckey_hex.hex_decode();

	int kpr = secp256k1_keypair_create(ctx, &keypair, seckey_bytes.ptr());
	assert(kpr == 1);

	int pubkey_create_r = secp256k1_keypair_xonly_pub(ctx, &pubkey, nullptr, &keypair);
	assert(pubkey_create_r == 1);

	unsigned char serialized_pubkey[32];
	int pubkey_serialize_r = secp256k1_xonly_pubkey_serialize(ctx, serialized_pubkey, &pubkey);
	assert(pubkey_serialize_r == 1);

	PackedByteArray pubkey_bytes;
	pubkey_bytes.resize(32);
	for (int i = 0; i < 32; ++i) {
		pubkey_bytes.set(i, serialized_pubkey[i]);
	}
	// Write pubkey
	retval["pubkey"] = pubkey_bytes.hex_encode();

	// Clean up
	secp256k1_context_destroy(ctx);

	return retval;
}

String Nostr::sign(const String& msg, const String& seckey_hex) {
	secp256k1_context *ctx = get_randomized_context();

	// Decode seckey_hex to bytes
	PackedByteArray seckey_bytes = seckey_hex.hex_decode();

	secp256k1_keypair keypair;
	int kpr = secp256k1_keypair_create(ctx, &keypair, seckey_bytes.ptr());
	assert(kpr == 1);

	// Decode to bytes
	PackedByteArray msg_bytes = msg.to_utf8_buffer();
	// Sha256 the message
	Ref<HashingContext> hashing_context;
	hashing_context.instantiate();
	hashing_context->start(HashingContext::HASH_SHA256);
	hashing_context->update(msg_bytes);
	PackedByteArray msg_hash = hashing_context->finish();
	unsigned char sig64[64];

	Ref<Crypto> crypto;
	crypto.instantiate();

	PackedByteArray aux_rand = crypto->generate_random_bytes(32);

	int sign_r = secp256k1_schnorrsig_sign32(
		ctx,
		sig64,
		msg_hash.ptr(),
		&keypair,
		aux_rand.ptr()
	);

	assert(sign_r == 1);
	PackedByteArray sig_bytes;
	sig_bytes.resize(64);
	for (int i = 0; i < 64; ++i) {
		sig_bytes.set(i, sig64[i]);
	}

	// Clean up
	secp256k1_context_destroy(ctx);
	return sig_bytes.hex_encode();
}

String Nostr::get_id_for_event(const String& event_string) {
	Ref<HashingContext> hashing_context;
	hashing_context.instantiate();
	hashing_context->start(HashingContext::HASH_SHA256);
	PackedByteArray event_string_bytes = event_string.to_utf8_buffer();
	hashing_context->update(event_string_bytes);
	PackedByteArray event_hash = hashing_context->finish();
	return event_hash.hex_encode();
}

String Nostr::get_event_string(const Dictionary& event) {
	// Verify that event has required fields
	if (!event.has("pubkey") || !event.has("created_at") ||
		!event.has("kind") || !event.has("tags") || !event.has("content")) {
		return String(); // Return empty string on error
	}

	Ref<JSON> json;
    json.instantiate();

	// [0,<pubkey_hex string>,<created_at number>,<kind number>,<tags array of arrays>,<content string>]
	// Build the message to sign
	Array msg_array;
	msg_array.append(0); // Version
	msg_array.append(event["pubkey"]);
	msg_array.append(int(event["created_at"])); // Force to int
	msg_array.append(int(event["kind"])); // Force to int
	msg_array.append(event["tags"]);
	msg_array.append(event["content"]);
	String msg_json = json->stringify(msg_array);

	return msg_json;
}

Dictionary Nostr::sign_event(const Dictionary& event, const String& seckey_hex) {
	// TODO: Validate event fields more thoroughly?
	String event_string = get_event_string(event);
	String event_id = get_id_for_event(event_string);

	if (event_id == String() || event_string == String()) {
		return Dictionary(); // Return empty dictionary on error
	}

	String sig = sign(event_string, seckey_hex);

	Dictionary retval = Dictionary();
	retval["id"] = event_id;
	retval["pubkey"] = event["pubkey"];
	retval["created_at"] = int(event["created_at"]); // Ensure created_at is int
	retval["kind"] = int(event["kind"]); // Ensure kind is int
	retval["tags"] = event["tags"];
	retval["content"] = event["content"];
	retval["sig"] = sig;
	return retval;
}

String Nostr::hex_to_nsec(const String& seckey_hex) {
	char bech32_seckey[128];
	CharString seckey_hex_cs = seckey_hex.utf8();
	if (bech32_encode_hex("nsec", seckey_hex_cs.get_data(), bech32_seckey, sizeof(bech32_seckey))) {
		return String(bech32_seckey);
	} else {
		return String();
	}
}

String Nostr::nsec_to_hex(const String& bech32_seckey) {
	char seckey_hex[128];
	CharString bech32_seckey_cs = bech32_seckey.utf8();
	size_t seckey_hex_len = 0;
	if (bech32_decode_hex(bech32_seckey_cs.get_data(), nullptr, 0, seckey_hex, sizeof(seckey_hex), &seckey_hex_len)) {
		return String(seckey_hex);
	} else {
		return String();
	}
}

String Nostr::hex_to_npub(const String& pubkey_hex) {
	char bech32_pubkey[128];
	CharString pubkey_hex_cs = pubkey_hex.utf8();
	if (bech32_encode_hex("npub", pubkey_hex_cs.get_data(), bech32_pubkey, sizeof(bech32_pubkey))) {
		return String(bech32_pubkey);
	} else {
		return String();
	}
}

String Nostr::npub_to_hex(const String& bech32_pubkey) {
	char pubkey_hex[128];
	CharString bech32_pubkey_cs = bech32_pubkey.utf8();
	size_t pubkey_hex_len = 0;
	if (bech32_decode_hex(bech32_pubkey_cs.get_data(), nullptr, 0, pubkey_hex, sizeof(pubkey_hex), &pubkey_hex_len)) {
		return String(pubkey_hex);
	} else {
		return String();
	}
}

secp256k1_context* Nostr::get_randomized_context() {
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	if (ctx == nullptr) {
		print_line("Failed to create secp256k1 context");
		return nullptr;
	}

	// Use secure_random to generate 32 bytes of randomness
	uint8_t rand32[32];
	if (!secure_random_bytes(rand32, sizeof(rand32))) {
		print_line("Failed to generate secure random bytes for context randomization");
		secp256k1_context_destroy(ctx);
		return nullptr;
	}

	// Randomize context
	int rctxr = secp256k1_context_randomize(ctx, rand32);
	assert(rctxr == 1);

	return ctx;
}

void Nostr::_bind_methods() {
	ClassDB::bind_static_method("Nostr", D_METHOD("create_new_keypair"), &Nostr::create_new_keypair);
	ClassDB::bind_static_method("Nostr", D_METHOD("keypair_from_seckey", "seckey_hex"), &Nostr::keypair_from_seckey);
	ClassDB::bind_static_method("Nostr", D_METHOD("sign", "msg", "seckey_hex"), &Nostr::sign);
	ClassDB::bind_static_method("Nostr", D_METHOD("hex_to_nsec", "seckey_hex"), &Nostr::hex_to_nsec);
	ClassDB::bind_static_method("Nostr", D_METHOD("nsec_to_hex", "bech32_seckey"), &Nostr::nsec_to_hex);
	ClassDB::bind_static_method("Nostr", D_METHOD("hex_to_npub", "pubkey_hex"), &Nostr::hex_to_npub);
	ClassDB::bind_static_method("Nostr", D_METHOD("npub_to_hex", "bech32_pubkey"), &Nostr::npub_to_hex);
	ClassDB::bind_static_method("Nostr", D_METHOD("sign_event", "event", "seckey_hex"), &Nostr::sign_event);
	ClassDB::bind_method(D_METHOD("request_create_new_keypair_pow", "min_leading_zero_bits"), &Nostr::request_create_new_keypair_pow);

	ClassDB::bind_method(D_METHOD("_pow_task", "min_leading_zero_bits"), &Nostr::_pow_task);
    ClassDB::bind_method(D_METHOD("_pow_task_done", "result"), &Nostr::_pow_task_done);

	ADD_SIGNAL(MethodInfo("keypair_pow_done", PropertyInfo(Variant::DICTIONARY, "result")));
	// ClassDB::bind_method(D_METHOD("generate_key"), &Nostr::generate_key);
	// ClassDB::bind_method(D_METHOD("key_from_seckey", "seckey_hex"), &Nostr::key_from_seckey);
	// ClassDB::bind_method(D_METHOD("sign", "msg", "seckey_hex"), &Nostr::sign);
}
