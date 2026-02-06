#pragma once

#include "godot_cpp/classes/ref_counted.hpp"
#include "godot_cpp/variant/dictionary.hpp"
#include <atomic>

extern "C" {
	#include <secp256k1.h>
	#include <secp256k1_extrakeys.h>
	#include <secp256k1_schnorrsig.h>
	#include <bech32.h>
}

#include <secure_random.h>
#include <hex_utils.h>
#include <sha256.h>

using namespace godot;

class Nostr : public RefCounted {
	GDCLASS(Nostr, RefCounted)

protected:
	static void _bind_methods();
	static secp256k1_context* get_randomized_context();

	static int _count_leading_zero_bits(const uint8_t* data, size_t data_len);

	std::atomic<bool> _pow_keypair_found{false};
    std::atomic<bool> _pow_keypair_working{false};

	void _pow_task_keypair(int min_leading_zero_bits);
	void _pow_task_keypair_done(const Dictionary& result);
	Dictionary _create_new_keypair_pow(int min_leading_zero_bits);

	std::atomic<bool> _pow_event_found{false};
	std::atomic<bool> _pow_event_working{false};

	void _pow_task_sign_event(const Dictionary& event, int min_leading_zero_bits, const String& seckey_hex);
	void _pow_task_sign_event_done(const Dictionary& result);

private:

	void request_create_new_keypair_pow(int min_leading_zero_bits);
	void request_sign_event_pow(const Dictionary& event, int min_leading_zero_bits, const String& seckey_hex);

	static Dictionary create_new_keypair();
	static Dictionary keypair_from_seckey(const String& seckey_hex);
	static String sign(const String& msg, const String& seckey_hex);
	static Dictionary sign_event(const Dictionary& event, const String& seckey_hex);
	static String get_id_for_event(const String& event);
	static String get_event_string(const Dictionary& event);
	static String hex_to_nsec(const String& seckey_hex);
	static String nsec_to_hex(const String& bech32_seckey);
	static String hex_to_npub(const String& pubkey_hex);
	static String npub_to_hex(const String& bech32_pubkey);
};
