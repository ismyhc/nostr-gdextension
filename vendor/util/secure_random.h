/* secure_random.h
   Cross-platform cryptographically secure random bytes (C, single-header).

   Supports:
     - Emscripten (Web): emscripten_get_random_bytes()
     - Windows:         BCryptGenRandom()
     - Apple/BSD:       arc4random_buf()
     - Linux/Android:   getrandom() syscall with /dev/urandom fallback
     - Other Unix:      /dev/urandom fallback

   Usage:
     #include "secure_random.h"

     uint8_t sk[32];
     if (!secure_random_bytes(sk, sizeof(sk))) { ... }

   License: Public domain / CC0-ish.
*/
/* secure_random.h
   Cross-platform cryptographically secure random bytes (C, single-header).
   ...
*/
#ifndef SECURE_RANDOM_H
#define SECURE_RANDOM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 1 on success, 0 on failure. */
static inline int secure_random_bytes(void *out, size_t out_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#if defined(__EMSCRIPTEN__)
  #include <errno.h>
  #include <fcntl.h>
  #include <unistd.h>

  static int secure_random_read_all(int fd, void *out, size_t out_len) {
    uint8_t *p = (uint8_t *)out;
    while (out_len) {
      ssize_t r = read(fd, p, out_len);
      if (r < 0) {
        if (errno == EINTR) continue;
        return 0;
      }
      if (r == 0) return 0;
      p += (size_t)r;
      out_len -= (size_t)r;
    }
    return 1;
  }

  int secure_random_bytes(void *out, size_t out_len) {
    if (!out && out_len) return 0;
    if (out_len == 0) return 1;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    int ok = secure_random_read_all(fd, out, out_len);
    close(fd);
    return ok;
  }

#elif defined(_WIN32)

  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #include <bcrypt.h>

  static inline int secure_random_bytes(void *out, size_t out_len) {
    if (!out && out_len) return 0;
    if (out_len > 0xFFFFFFFFu) return 0;
    NTSTATUS st = BCryptGenRandom(
      NULL,
      (PUCHAR)out,
      (ULONG)out_len,
      BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    return st == 0;
  }

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)

  #include <stdlib.h>

  static inline int secure_random_bytes(void *out, size_t out_len) {
    if (!out && out_len) return 0;
    arc4random_buf(out, out_len);
    return 1;
  }

#else /* Linux/Android/other Unix */

  #include <errno.h>
  #include <fcntl.h>
  #include <unistd.h>

  static inline int secure_random_read_all(int fd, void *out, size_t out_len) {
    uint8_t *p = (uint8_t *)out;
    while (out_len) {
      ssize_t r = read(fd, p, out_len);
      if (r < 0) {
        if (errno == EINTR) continue;
        return 0;
      }
      if (r == 0) return 0;
      p += (size_t)r;
      out_len -= (size_t)r;
    }
    return 1;
  }

  static inline int secure_random_urandom(void *out, size_t out_len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    int ok = secure_random_read_all(fd, out, out_len);
    close(fd);
    return ok;
  }

  #if defined(__linux__)
    #include <sys/syscall.h>
    #include <unistd.h>

    static inline int secure_random_getrandom(void *out, size_t out_len) {
      uint8_t *p = (uint8_t *)out;
      while (out_len) {
        long r = syscall(SYS_getrandom, p, out_len, 0);
        if (r < 0) {
          if (errno == EINTR) continue;
          return 0;
        }
        p += (size_t)r;
        out_len -= (size_t)r;
      }
      return 1;
    }
  #endif

  static inline int secure_random_bytes(void *out, size_t out_len) {
    if (!out && out_len) return 0;
    if (out_len == 0) return 1;

    #if defined(__linux__)
      if (secure_random_getrandom(out, out_len)) return 1;
    #endif
    return secure_random_urandom(out, out_len);
  }

#endif /* platform selection */
#endif /* SECURE_RANDOM_H */
