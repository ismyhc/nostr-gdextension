#ifndef NOSTR_BECH32_H
#define NOSTR_BECH32_H

/*
 * Minimal Bech32 encoder (BIP-0173) for Nostr use.
 * Header-only, plain C.
 *
 * Usage (encode hex -> bech32):
 *   const char *hex = "f3c2..."; // 64 hex chars (32 bytes)
 *   char out[128];
 *   if (bech32_encode_hex("npub", hex, out, sizeof(out))) {
 *       // out = "npub1..."
 *   }
 *
 * Usage (decode bech32 -> hex):
 *   char hrp[8];
 *   char hex_out[128];
 *   size_t bytes_len = 0;
 *   if (bech32_decode_hex("npub1...", hrp, sizeof(hrp),
 *                         hex_out, sizeof(hex_out), &bytes_len)) {
 *       // hrp = "npub", hex_out = original hex
 *   }
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline int bech32__hex_nibble(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static inline size_t bech32__hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
	size_t hex_len = strlen(hex);
	size_t i = 0;
	size_t j = 0;

	if ((hex_len % 2) != 0) return 0;
	if ((hex_len / 2) > out_len) return 0;

	while (i < hex_len) {
		int hi = bech32__hex_nibble(hex[i]);
		int lo = bech32__hex_nibble(hex[i + 1]);
		if (hi < 0 || lo < 0) return 0;
		out[j++] = (uint8_t)((hi << 4) | lo);
		i += 2;
	}
	return j;
}

static inline size_t bech32__convert_bits(uint8_t *out, size_t out_len,
										  int out_bits, const uint8_t *in,
										  size_t in_len, int in_bits, int pad) {
	uint32_t acc = 0;
	int bits = 0;
	size_t j = 0;
	uint32_t maxv = ((uint32_t)1 << out_bits) - 1;

	for (size_t i = 0; i < in_len; ++i) {
		acc = (acc << in_bits) | in[i];
		bits += in_bits;
		while (bits >= out_bits) {
			bits -= out_bits;
			if (j >= out_len) return 0;
			out[j++] = (uint8_t)((acc >> bits) & maxv);
		}
	}

	if (pad) {
		if (bits > 0) {
			if (j >= out_len) return 0;
			out[j++] = (uint8_t)((acc << (out_bits - bits)) & maxv);
		}
	} else {
		if (bits >= in_bits) return 0;
		if (((acc << (out_bits - bits)) & maxv) != 0) return 0;
	}

	return j;
}

static inline uint32_t bech32__polymod(const uint8_t *values, size_t len) {
	static const uint32_t GEN[5] = {
		0x3b6a57b2,
		0x26508e6d,
		0x1ea119fa,
		0x3d4233dd,
		0x2a1462b3
	};
	uint32_t chk = 1;
	for (size_t i = 0; i < len; ++i) {
		uint8_t top = (uint8_t)(chk >> 25);
		chk = (chk & 0x1ffffffu) << 5 ^ values[i];
		for (int j = 0; j < 5; ++j) {
			if ((top >> j) & 1) {
				chk ^= GEN[j];
			}
		}
	}
	return chk;
}

static inline size_t bech32__hrp_expand(const char *hrp, uint8_t *out, size_t out_len) {
	size_t hrp_len = strlen(hrp);
	size_t needed = hrp_len * 2 + 1;
	if (out_len < needed) return 0;

	size_t i = 0;
	for (; i < hrp_len; ++i) {
		out[i] = (uint8_t)(hrp[i] >> 5);
	}
	out[i++] = 0;
	for (size_t j = 0; j < hrp_len; ++j, ++i) {
		out[i] = (uint8_t)(hrp[j] & 31);
	}
	return needed;
}

static inline int bech32__create_checksum(const char *hrp, const uint8_t *data,
										  size_t data_len, uint8_t *out6) {
	size_t hrp_len = strlen(hrp);
	size_t buf_len = (hrp_len * 2 + 1) + data_len + 6;

	uint8_t *buf = (uint8_t *)malloc(buf_len);
	if (!buf) return 0;

	size_t off = bech32__hrp_expand(hrp, buf, buf_len);
	if (off == 0) {
		free(buf);
		return 0;
	}

	memcpy(buf + off, data, data_len);
	memset(buf + off + data_len, 0, 6);

	uint32_t pm = bech32__polymod(buf, off + data_len + 6) ^ 1;
	for (int i = 0; i < 6; ++i) {
		out6[i] = (uint8_t)((pm >> (5 * (5 - i))) & 31);
	}

	free(buf);
	return 1;
}

static inline int bech32_encode(const char *hrp, const uint8_t *data, size_t data_len,
								char *output, size_t output_len) {
	static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
	size_t hrp_len = strlen(hrp);
	size_t data5_len = (data_len * 8 + 4) / 5;
	size_t needed = hrp_len + 1 + data5_len + 6 + 1;

	if (output_len < needed) return 0;

	uint8_t *data5 = (uint8_t *)malloc(data5_len);
	if (!data5) return 0;

	size_t conv = bech32__convert_bits(data5, data5_len, 5, data, data_len, 8, 1);
	if (conv != data5_len) {
		free(data5);
		return 0;
	}

	uint8_t checksum[6];
	if (!bech32__create_checksum(hrp, data5, data5_len, checksum)) {
		free(data5);
		return 0;
	}

	size_t pos = 0;
	for (size_t i = 0; i < hrp_len; ++i) {
		char c = hrp[i];
		output[pos++] = (char)tolower((unsigned char)c);
	}
	output[pos++] = '1';

	for (size_t i = 0; i < data5_len; ++i) {
		output[pos++] = CHARSET[data5[i]];
	}
	for (size_t i = 0; i < 6; ++i) {
		output[pos++] = CHARSET[checksum[i]];
	}
	output[pos] = '\0';
	free(data5);
	return 1;
}

static inline int bech32_encode_hex(const char *hrp, const char *hex,
									char *output, size_t output_len) {
	size_t hex_len = strlen(hex);
	size_t byte_len = hex_len / 2;

	uint8_t *bytes = (uint8_t *)malloc(byte_len);
	if (!bytes) return 0;

	size_t parsed = bech32__hex_to_bytes(hex, bytes, byte_len);
	if (parsed == 0) {
		free(bytes);
		return 0;
	}
	int ok = bech32_encode(hrp, bytes, parsed, output, output_len);
	free(bytes);
	return ok;
}

static inline int bech32__charset_val(char c) {
	static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
	const char *p = strchr(CHARSET, c);
	if (!p) return -1;
	return (int)(p - CHARSET);
}

static inline int bech32__verify_checksum(const char *hrp, const uint8_t *data, size_t data_len) {
	size_t hrp_len = strlen(hrp);
	size_t buf_len = (hrp_len * 2 + 1) + data_len;

	uint8_t *buf = (uint8_t *)malloc(buf_len);
	if (!buf) return 0;

	size_t off = bech32__hrp_expand(hrp, buf, buf_len);
	if (off == 0) {
		free(buf);
		return 0;
	}

	memcpy(buf + off, data, data_len);
	uint32_t pm = bech32__polymod(buf, off + data_len);
	free(buf);
	return pm == 1;
}

static inline int bech32_decode(const char *input,
								char *hrp, size_t hrp_len,
								uint8_t *data, size_t data_len,
								size_t *data_out_len) {
	size_t in_len = strlen(input);
	if (in_len < 8) return 0;

	int has_lower = 0;
	int has_upper = 0;
	for (size_t i = 0; i < in_len; ++i) {
		unsigned char c = (unsigned char)input[i];
		if (c < 33 || c > 126) return 0;
		if (c >= 'a' && c <= 'z') has_lower = 1;
		if (c >= 'A' && c <= 'Z') has_upper = 1;
	}
	if (has_lower && has_upper) return 0;

	size_t sep = 0;
	for (size_t i = 0; i < in_len; ++i) {
		if (input[i] == '1') sep = i;
	}
	if (sep == 0 || sep + 7 > in_len) return 0;

	size_t hrp_in_len = sep;
	if (hrp_in_len + 1 > hrp_len) return 0;

	for (size_t i = 0; i < hrp_in_len; ++i) {
		hrp[i] = (char)tolower((unsigned char)input[i]);
	}
	hrp[hrp_in_len] = '\0';

	size_t data5_len = in_len - sep - 1;
	if (data5_len < 6) return 0;

	uint8_t *data5 = (uint8_t *)malloc(data5_len);
	if (!data5) return 0;

	for (size_t i = 0; i < data5_len; ++i) {
		char c = (char)tolower((unsigned char)input[sep + 1 + i]);
		int v = bech32__charset_val(c);
		if (v < 0) {
			free(data5);
			return 0;
		}
		data5[i] = (uint8_t)v;
	}

	if (!bech32__verify_checksum(hrp, data5, data5_len)) {
		free(data5);
		return 0;
	}

	size_t payload5_len = data5_len - 6;
	size_t max_out = (payload5_len * 5) / 8;
	if (data_len < max_out) {
		free(data5);
		return 0;
	}

	size_t out_len = bech32__convert_bits(data, data_len, 8, data5, payload5_len, 5, 0);
	free(data5);
	if (out_len == 0) return 0;

	if (data_out_len) *data_out_len = out_len;
	return 1;
}

static inline int bech32__bytes_to_hex(const uint8_t *bytes, size_t bytes_len,
									   char *hex_out, size_t hex_out_len) {
	static const char *HEX = "0123456789abcdef";
	if (hex_out_len < bytes_len * 2 + 1) return 0;
	for (size_t i = 0; i < bytes_len; ++i) {
		hex_out[i * 2] = HEX[(bytes[i] >> 4) & 0x0F];
		hex_out[i * 2 + 1] = HEX[bytes[i] & 0x0F];
	}
	hex_out[bytes_len * 2] = '\0';
	return 1;
}

static inline int bech32_decode_hex(const char *input,
									char *hrp, size_t hrp_len,
									char *hex_out, size_t hex_out_len,
									size_t *bytes_len_out) {
	size_t in_len = strlen(input);
	size_t max_bytes = (in_len * 5) / 8;
	uint8_t *bytes = (uint8_t *)malloc(max_bytes);
	if (!bytes) return 0;

	size_t bytes_len = 0;
	int ok = bech32_decode(input, hrp, hrp_len, bytes, max_bytes, &bytes_len);
	if (!ok) {
		free(bytes);
		return 0;
	}
	if (!bech32__bytes_to_hex(bytes, bytes_len, hex_out, hex_out_len)) {
		free(bytes);
		return 0;
	}
	if (bytes_len_out) *bytes_len_out = bytes_len;
	free(bytes);
	return 1;
}

#ifdef __cplusplus
}
#endif

#endif
