#include "nostr.hpp" // For headers that are our own, we use ""
#include "godot_cpp/core/class_db.hpp"
#include <cassert>
#include <cstring>

#include <godot_cpp/classes/crypto.hpp>

#pragma once
extern "C" {
	#include <secp256k1.h>
	#include <secp256k1_extrakeys.h>
	#include <secp256k1_schnorrsig.h>
	#include "bech32.h"
}

using namespace godot;

Dictionary Nostr::generate_key() {
	Dictionary retval;

	secp256k1_xonly_pubkey pubkey;
	secp256k1_keypair keypair;

	secp256k1_context *ctx = get_randomized_context();

	Ref<Crypto> crypto;
	crypto.instantiate();

	PackedByteArray seckey = crypto->generate_random_bytes(32);
	int kpr = secp256k1_keypair_create(ctx, &keypair, seckey.ptr());
	assert(kpr == 1);

	int pubkey_create_r = secp256k1_keypair_xonly_pub(ctx, &pubkey, nullptr, &keypair);
	assert(pubkey_create_r == 1);

	unsigned char serialized_pubkey[32];
	int pubkey_serialize_r = secp256k1_xonly_pubkey_serialize(ctx, serialized_pubkey, &pubkey);
	assert(pubkey_serialize_r == 1);

	// Write seckey
	retval["seckey"] = PackedByteArray(seckey).hex_encode();

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

Dictionary Nostr::key_from_seckey(const String& seckey_hex) {
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

secp256k1_context* Nostr::get_randomized_context() {
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	if (ctx == nullptr) {
		print_line("Failed to create secp256k1 context");
		return nullptr;
	}

	Ref<Crypto> crypto;
	crypto.instantiate();
	PackedByteArray ctx_random = crypto->generate_random_bytes(32);
	int rctxr = secp256k1_context_randomize(ctx, ctx_random.ptr());
	assert(rctxr == 1);

	return ctx;
}

void Nostr::_bind_methods() {
	ClassDB::bind_static_method("Nostr", D_METHOD("generate_key"), &Nostr::generate_key);
	ClassDB::bind_static_method("Nostr", D_METHOD("key_from_seckey", "seckey_hex"), &Nostr::key_from_seckey);
	ClassDB::bind_static_method("Nostr", D_METHOD("sign", "msg", "seckey_hex"), &Nostr::sign);
	// ClassDB::bind_method(D_METHOD("generate_key"), &Nostr::generate_key);
	// ClassDB::bind_method(D_METHOD("key_from_seckey", "seckey_hex"), &Nostr::key_from_seckey);
	// ClassDB::bind_method(D_METHOD("sign", "msg", "seckey_hex"), &Nostr::sign);
}
