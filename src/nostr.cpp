#include "nostr.hpp"
#include "godot_cpp/classes/rendering_device.hpp"
#include "godot_cpp/core/class_db.hpp"
#include "godot_cpp/core/object.hpp"
#include "godot_cpp/variant/array.hpp"
#include "godot_cpp/variant/dictionary.hpp"
#include "godot_cpp/variant/packed_byte_array.hpp"
#include "godot_cpp/variant/string.hpp"
#include <godot_cpp/classes/json.hpp>
#include <godot_cpp/classes/os.hpp>
#include <cassert>
#include <cstring>

#include <godot_cpp/classes/crypto.hpp>
#include <godot_cpp/classes/worker_thread_pool.hpp>
#include <godot_cpp/variant/utility_functions.hpp>

//#pragma once

using namespace godot;

void Nostr::request_sign_event_pow(const Dictionary& event, int min_leading_zero_bits, const String& seckey_hex) {
	if (_pow_event_working.load(std::memory_order_relaxed)) {
		UtilityFunctions::print("Nostr: Event POW already in progress, ignoring new request");
		return;
	}
	int cores = OS::get_singleton()->get_processor_count();
	int workers = cores - 1;
	if (workers < 1) workers = 1;
	UtilityFunctions::print("Starting ", workers, " worker threads for Event POW");

	_pow_event_found.store(false, std::memory_order_relaxed);
	_pow_event_working.store(true,  std::memory_order_relaxed);
	for (int i = 0; i < workers; ++i) {
		WorkerThreadPool::get_singleton()->add_task(
			Callable(this, "_pow_task_sign_event").bind(event, min_leading_zero_bits, seckey_hex),
			true
		);
	}
}

void Nostr::_pow_task_sign_event(const Dictionary& event, int min_leading_zero_bits, const String& seckey_hex) {
	UtilityFunctions::print("Nostr: Starting Event POW task");
	if (_pow_event_found.load(std::memory_order_relaxed)) return;

	// Here we add nonce to the event tags, we need to append a tag like ["nonce", <random 32 byte hex string>, <leading zero bits>]
	// Nonce array
	Array nonce_tag;
	nonce_tag.append("nonce");
	unsigned char nonce_bytes[32]; // nonce bytes can be alot shorter than 32 bytes, but we will hex encode it to 64 chars, so we use 32 bytes here
	if (!secure_random_bytes(nonce_bytes, sizeof(nonce_bytes))) {
		print_line("Failed to generate secure random nonce");
		return;
	}
	char nonce_hex[65];
	size_t nonce_hex_len = bytes_to_hex(nonce_hex, sizeof(nonce_hex), nonce_bytes, 32);
	nonce_tag.append(String::utf8(nonce_hex, (int)nonce_hex_len));
	nonce_tag.append(min_leading_zero_bits);

	Array tags = event["tags"];
	tags.append(nonce_tag);
	//event["tags"] = tags; TODO:

	String event_string = get_event_string(event);
	String event_id = get_id_for_event(event_string);




	Dictionary result = sign_event(event, seckey_hex);
	bool expected = false;
	if (_pow_event_found.compare_exchange_strong(expected, true, std::memory_order_relaxed)) {
		_pow_event_working.store(false, std::memory_order_relaxed);
		call_deferred("_pow_task_sign_event_done", result);
	}
}

void Nostr::_pow_task_sign_event_done(const Dictionary& result) {
	UtilityFunctions::print("Nostr: Event POW task done");
	emit_signal("sign_event_pow_done", result);
}

// Dictionary Nostr::sign_event_pow(Dictionary& event, int min_leading_zero_bits, const String& seckey_hex) {

// 	int iterations_count = 0;
// 	while (true) {

// 	}
// }



void Nostr::request_create_new_keypair_pow(int min_leading_zero_bits) {
	if (_pow_keypair_working.load(std::memory_order_relaxed)) {
		UtilityFunctions::print("Nostr: POW already in progress, ignoring new request");
		return;
	}
	int cores = OS::get_singleton()->get_processor_count();
	int workers = cores - 1;
	if (workers < 1) workers = 1;
	UtilityFunctions::print("Starting ", workers, " worker threads for POW");

	_pow_keypair_found.store(false, std::memory_order_relaxed);
	_pow_keypair_working.store(true,  std::memory_order_relaxed);
	for (int i = 0; i < workers; ++i) {
		WorkerThreadPool::get_singleton()->add_task(
			Callable(this, "_pow_task_keypair").bind(min_leading_zero_bits),
			true
		);
	}
}

// Functions not exposed to Godot, used internally
void Nostr::_pow_task_keypair(int min_leading_zero_bits) {
	UtilityFunctions::print("Nostr: Starting Keypair POW task");
	if (_pow_keypair_found.load(std::memory_order_relaxed)) return;
	Dictionary result = _create_new_keypair_pow(min_leading_zero_bits);
	bool expected = false;
	if (_pow_keypair_found.compare_exchange_strong(expected, true, std::memory_order_relaxed)) {
		_pow_keypair_working.store(false, std::memory_order_relaxed);
    	call_deferred("_pow_task_keypair_done", result);
	}
}

void Nostr::_pow_task_keypair_done(const Dictionary& result) {
	UtilityFunctions::print("Nostr: Keypair POW task done");
    emit_signal("keypair_pow_done", result);
}

Dictionary Nostr::_create_new_keypair_pow(int min_leading_zero_bits) {
	Dictionary retval;

	secp256k1_xonly_pubkey pubkey;
	secp256k1_keypair keypair;
	secp256k1_context *ctx = get_randomized_context();

	int iterations_count = 0;
	while (true) {
		iterations_count++;
		// check if another thread found a result
		if (_pow_keypair_found.load(std::memory_order_relaxed)) {
			return Dictionary();
		}

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

		int leading_zero_bits = _count_leading_zero_bits(serialized_pubkey, 32);
		if (leading_zero_bits >= min_leading_zero_bits) {

			Dictionary keypair;

			// hex encode seckey
			String seckey_hex;
			{
				char seckey_hex_buf[65];
				size_t seckey_hex_len = bytes_to_hex(seckey_hex_buf, sizeof(seckey_hex_buf), seckey, 32);
				seckey_hex = String::utf8(seckey_hex_buf, (int)seckey_hex_len);
			}

			keypair["seckey"] = seckey_hex;

			// hex encode pubkey
			String pubkey_hex;
			{
				char pubkey_hex_buf[65];
				size_t pubkey_hex_len = bytes_to_hex(pubkey_hex_buf, sizeof(pubkey_hex_buf), serialized_pubkey, 32);
				pubkey_hex = String::utf8(pubkey_hex_buf, (int)pubkey_hex_len);
			}

			keypair["pubkey"] = pubkey_hex;

			// // Encode seckey to bech32
			char bech32_seckey[128];
			CharString seckey_hex_cs = seckey_hex.utf8();
			if (bech32_encode_hex("nsec", seckey_hex_cs.get_data(), bech32_seckey, sizeof(bech32_seckey))) {
				keypair["nsec"] = String(bech32_seckey);
			} else {
				keypair["nsec"] = String();
			}

			// // Encode pubkey to bech32
			char bech32_pubkey[128];
			CharString pubkey_hex_cs = pubkey_hex.utf8();
			if (bech32_encode_hex("npub", pubkey_hex_cs.get_data(), bech32_pubkey, sizeof(bech32_pubkey))) {
				keypair["npub"] = String(bech32_pubkey);
			} else {
				keypair["npub"] = String();
			}

			retval["keypair"] = keypair;
			retval["leading_zero_bits"] = leading_zero_bits;
			retval["iterations"] = iterations_count;

			break;
		}
	}

	// Clean up
	secp256k1_context_destroy(ctx);

	return retval;
}




int Nostr::_count_leading_zero_bits(const uint8_t* data, size_t data_len) {
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
	char bech32_seckey[128];
	CharString seckey_hex_cs = seckey_hex.utf8();
	if (bech32_encode_hex("nsec", seckey_hex_cs.get_data(), bech32_seckey, sizeof(bech32_seckey))) {
		retval["nsec"] = String(bech32_seckey);
	} else {
		retval["nsec"] = String();
	}

	// // Encode pubkey to bech32
	char bech32_pubkey[128];
	CharString pubkey_hex_cs = pubkey_hex.utf8();
	if (bech32_encode_hex("npub", pubkey_hex_cs.get_data(), bech32_pubkey, sizeof(bech32_pubkey))) {
		retval["npub"] = String(bech32_pubkey);
	} else {
		retval["npub"] = String();
	}

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
	CharString utf8 = event_string.utf8();

    uint8_t hash[32];
    sha256((const uint8_t *)utf8.get_data(), (uint64_t)utf8.length(), hash);

    char hex[65];
    size_t written = bytes_to_hex(hex, sizeof(hex), hash, sizeof(hash));
    if (written == 0) {
        return String();
    }
    return String::utf8(hex, (int)written);
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
	ClassDB::bind_method(D_METHOD("_pow_task_keypair", "min_leading_zero_bits"), &Nostr::_pow_task_keypair);
    ClassDB::bind_method(D_METHOD("_pow_task_keypair_done", "result"), &Nostr::_pow_task_keypair_done);
	ADD_SIGNAL(MethodInfo("keypair_pow_done", PropertyInfo(Variant::DICTIONARY, "result")));

	ClassDB::bind_method(D_METHOD("request_sign_event_pow", "event", "min_leading_zero_bits", "seckey_hex"), &Nostr::request_sign_event_pow);
	ClassDB::bind_method(D_METHOD("_pow_task_sign_event", "event", "min_leading_zero_bits", "seckey_hex"), &Nostr::_pow_task_sign_event);
	ClassDB::bind_method(D_METHOD("_pow_task_sign_event_done", "result"), &Nostr::_pow_task_sign_event_done);
	ADD_SIGNAL(MethodInfo("sign_event_pow_done", PropertyInfo(Variant::DICTIONARY, "result")));
}
