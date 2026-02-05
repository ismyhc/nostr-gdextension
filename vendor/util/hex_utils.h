/* hex_utils.h
   Cross-platform hex encode/decode (pure C, single-header).
   - bytes_to_hex: encodes bytes to lowercase hex, NUL-terminated
   - hex_to_bytes: decodes hex to bytes (accepts upper/lower), rejects invalid

   Usage:
     #define HEX_UTILS_IMPLEMENTATION
     #include "hex_utils.h"

   Notes:
     - bytes_to_hex requires dst_len >= (src_len*2 + 1)
     - hex_to_bytes requires even-length hex; can optionally allow "0x" prefix
*/

#ifndef HEX_UTILS_H
#define HEX_UTILS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns number of chars written excluding NUL (i.e. src_len*2) on success, 0 on failure. */
static inline size_t bytes_to_hex(char *dst, size_t dst_len, const uint8_t *src, size_t src_len);

/* Returns number of bytes written to dst on success, 0 on failure. */
static inline size_t hex_to_bytes(uint8_t *dst, size_t dst_len, const char *hex, size_t hex_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

/* inline implementation (header-only, no macros needed) */
static inline int hex_nibble_value(unsigned char c) {
  if (c >= '0' && c <= '9') return (int)(c - '0');
  if (c >= 'a' && c <= 'f') return (int)(c - 'a') + 10;
  if (c >= 'A' && c <= 'F') return (int)(c - 'A') + 10;
  return -1;
}

static inline size_t bytes_to_hex(char *dst, size_t dst_len, const uint8_t *src, size_t src_len) {
  static const char hexdigits[] = "0123456789abcdef";

  if (!dst && dst_len) return 0;
  if (!src && src_len) return 0;

  /* Need 2 chars per byte + NUL */
  if (dst_len < (src_len * 2u + 1u)) return 0;

  for (size_t i = 0; i < src_len; i++) {
    uint8_t b = src[i];
    dst[i * 2u + 0u] = hexdigits[(unsigned)(b >> 4)];
    dst[i * 2u + 1u] = hexdigits[(unsigned)(b & 0x0F)];
  }
  dst[src_len * 2u] = '\0';
  return src_len * 2u;
}

static inline size_t hex_to_bytes(uint8_t *dst, size_t dst_len, const char *hex, size_t hex_len) {
  if (!dst && dst_len) return 0;
  if (!hex) return 0;

  /* Optional 0x/0X prefix */
  if (hex_len >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
    hex += 2;
    hex_len -= 2;
  }

  if ((hex_len & 1u) != 0u) return 0; /* must be even length */

  size_t out_len = hex_len / 2u;
  if (out_len > dst_len) return 0;

  for (size_t i = 0; i < out_len; i++) {
    int hi = hex_nibble_value((unsigned char)hex[i * 2u + 0u]);
    int lo = hex_nibble_value((unsigned char)hex[i * 2u + 1u]);
    if (hi < 0 || lo < 0) return 0;
    dst[i] = (uint8_t)((hi << 4) | lo);
  }

  return out_len;
}

#endif /* HEX_UTILS_H */
