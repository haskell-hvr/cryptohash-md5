/*
 * Copyright (C) 2006-2009 Vincent Hanquez <vincent@snarc.org>
 *               2016      Herbert Valerio Riedel <hvr@gnu.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef CRYPTOHASH_MD5_H
#define CRYPTOHASH_MD5_H

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <ghcautoconf.h>

struct md5_ctx
{
	uint64_t sz;
	uint8_t  buf[64];
	uint32_t h[4];
};

#define MD5_DIGEST_SIZE		16
#define MD5_CTX_SIZE		88

static inline void hs_cryptohash_md5_init(struct md5_ctx *ctx);
static inline void hs_cryptohash_md5_update(struct md5_ctx *ctx, const uint8_t *data, size_t len);
static inline uint64_t hs_cryptohash_md5_finalize(struct md5_ctx *ctx, uint8_t *out);

#if defined(static_assert)
static_assert(sizeof(struct md5_ctx) == MD5_CTX_SIZE, "unexpected md5_ctx size");
#else
/* poor man's pre-C11 _Static_assert */
typedef char static_assertion__unexpected_md5_ctx_size[(sizeof(struct md5_ctx) == MD5_CTX_SIZE)?1:-1];
#endif

#define ptr_uint32_aligned(ptr) (!((uintptr_t)(ptr) & 0x3))

static inline uint32_t
rol32(const uint32_t word, const unsigned shift)
{
  /* GCC usually transforms this into a 'rol'-insn */
  return (word << shift) | (word >> (32 - shift));
}

static inline uint32_t
cpu_to_le32(const uint32_t hl)
{
#if !WORDS_BIGENDIAN
  return hl;
#elif __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
  return __builtin_bswap32(hl);
#else
  /* GCC usually transforms this into a bswap insn */
  return ((hl & 0xff000000) >> 24) |
         ((hl & 0x00ff0000) >> 8)  |
         ((hl & 0x0000ff00) << 8)  |
         ( hl               << 24);
#endif
}

static inline void
cpu_to_le32_array(uint32_t *dest, const uint32_t *src, unsigned wordcnt)
{
  while (wordcnt--)
    *dest++ = cpu_to_le32(*src++);
}

static inline uint64_t
cpu_to_le64(const uint64_t hll)
{
#if !WORDS_BIGENDIAN
  return hll;
#elif __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
  return __builtin_bswap64(hll);
#else
  return ((uint64_t)cpu_to_le32(hll & 0xffffffff) << 32LL) | cpu_to_le32(hll >> 32);
#endif
}


static inline void
hs_cryptohash_md5_init(struct md5_ctx *ctx)
{
  memset(ctx, 0, sizeof(*ctx));

  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xefcdab89;
  ctx->h[2] = 0x98badcfe;
  ctx->h[3] = 0x10325476;
}

#define f1(x, y, z)     (z ^ (x & (y ^ z)))
#define f2(x, y, z)     f1(z, x, y)
#define f3(x, y, z)     (x ^ y ^ z)
#define f4(x, y, z)     (y ^ (x | ~z))
#define R(f, a, b, c, d, i, k, s) a += f(b, c, d) + w[i] + k; a = rol32(a, s); a += b

static void
md5_do_chunk_aligned(struct md5_ctx *ctx, const uint32_t w[])
{
  uint32_t a = ctx->h[0];
  uint32_t b = ctx->h[1];
  uint32_t c = ctx->h[2];
  uint32_t d = ctx->h[3];

  R(f1, a, b, c, d,  0, 0xd76aa478,  7);
  R(f1, d, a, b, c,  1, 0xe8c7b756, 12);
  R(f1, c, d, a, b,  2, 0x242070db, 17);
  R(f1, b, c, d, a,  3, 0xc1bdceee, 22);
  R(f1, a, b, c, d,  4, 0xf57c0faf,  7);
  R(f1, d, a, b, c,  5, 0x4787c62a, 12);
  R(f1, c, d, a, b,  6, 0xa8304613, 17);
  R(f1, b, c, d, a,  7, 0xfd469501, 22);
  R(f1, a, b, c, d,  8, 0x698098d8,  7);
  R(f1, d, a, b, c,  9, 0x8b44f7af, 12);
  R(f1, c, d, a, b, 10, 0xffff5bb1, 17);
  R(f1, b, c, d, a, 11, 0x895cd7be, 22);
  R(f1, a, b, c, d, 12, 0x6b901122,  7);
  R(f1, d, a, b, c, 13, 0xfd987193, 12);
  R(f1, c, d, a, b, 14, 0xa679438e, 17);
  R(f1, b, c, d, a, 15, 0x49b40821, 22);

  R(f2, a, b, c, d,  1, 0xf61e2562,  5);
  R(f2, d, a, b, c,  6, 0xc040b340,  9);
  R(f2, c, d, a, b, 11, 0x265e5a51, 14);
  R(f2, b, c, d, a,  0, 0xe9b6c7aa, 20);
  R(f2, a, b, c, d,  5, 0xd62f105d,  5);
  R(f2, d, a, b, c, 10, 0x02441453,  9);
  R(f2, c, d, a, b, 15, 0xd8a1e681, 14);
  R(f2, b, c, d, a,  4, 0xe7d3fbc8, 20);
  R(f2, a, b, c, d,  9, 0x21e1cde6,  5);
  R(f2, d, a, b, c, 14, 0xc33707d6,  9);
  R(f2, c, d, a, b,  3, 0xf4d50d87, 14);
  R(f2, b, c, d, a,  8, 0x455a14ed, 20);
  R(f2, a, b, c, d, 13, 0xa9e3e905,  5);
  R(f2, d, a, b, c,  2, 0xfcefa3f8,  9);
  R(f2, c, d, a, b,  7, 0x676f02d9, 14);
  R(f2, b, c, d, a, 12, 0x8d2a4c8a, 20);

  R(f3, a, b, c, d,  5, 0xfffa3942,  4);
  R(f3, d, a, b, c,  8, 0x8771f681, 11);
  R(f3, c, d, a, b, 11, 0x6d9d6122, 16);
  R(f3, b, c, d, a, 14, 0xfde5380c, 23);
  R(f3, a, b, c, d,  1, 0xa4beea44,  4);
  R(f3, d, a, b, c,  4, 0x4bdecfa9, 11);
  R(f3, c, d, a, b,  7, 0xf6bb4b60, 16);
  R(f3, b, c, d, a, 10, 0xbebfbc70, 23);
  R(f3, a, b, c, d, 13, 0x289b7ec6,  4);
  R(f3, d, a, b, c,  0, 0xeaa127fa, 11);
  R(f3, c, d, a, b,  3, 0xd4ef3085, 16);
  R(f3, b, c, d, a,  6, 0x04881d05, 23);
  R(f3, a, b, c, d,  9, 0xd9d4d039,  4);
  R(f3, d, a, b, c, 12, 0xe6db99e5, 11);
  R(f3, c, d, a, b, 15, 0x1fa27cf8, 16);
  R(f3, b, c, d, a,  2, 0xc4ac5665, 23);

  R(f4, a, b, c, d,  0, 0xf4292244,  6);
  R(f4, d, a, b, c,  7, 0x432aff97, 10);
  R(f4, c, d, a, b, 14, 0xab9423a7, 15);
  R(f4, b, c, d, a,  5, 0xfc93a039, 21);
  R(f4, a, b, c, d, 12, 0x655b59c3,  6);
  R(f4, d, a, b, c,  3, 0x8f0ccc92, 10);
  R(f4, c, d, a, b, 10, 0xffeff47d, 15);
  R(f4, b, c, d, a,  1, 0x85845dd1, 21);
  R(f4, a, b, c, d,  8, 0x6fa87e4f,  6);
  R(f4, d, a, b, c, 15, 0xfe2ce6e0, 10);
  R(f4, c, d, a, b,  6, 0xa3014314, 15);
  R(f4, b, c, d, a, 13, 0x4e0811a1, 21);
  R(f4, a, b, c, d,  4, 0xf7537e82,  6);
  R(f4, d, a, b, c, 11, 0xbd3af235, 10);
  R(f4, c, d, a, b,  2, 0x2ad7d2bb, 15);
  R(f4, b, c, d, a,  9, 0xeb86d391, 21);

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
}

static void
md5_do_chunk(struct md5_ctx *ctx, const uint8_t buf[])
{
  if (ptr_uint32_aligned(buf)) { /* aligned buf */
#if WORDS_BIGENDIAN
    uint32_t w[16]; cpu_to_le32_array(w, (const uint32_t *)buf, 16);
#else
    const uint32_t *w = (const uint32_t *)buf;
#endif
    md5_do_chunk_aligned(ctx, w);
  } else { /* unaligned buf */
    uint32_t w[16]; memcpy(w, buf, 64);
#if WORDS_BIGENDIAN
    cpu_to_le32_array(w, w, 16);
#endif
    md5_do_chunk_aligned(ctx, w);
  }
}

static inline void
hs_cryptohash_md5_update(struct md5_ctx *ctx, const uint8_t *data, size_t len)
{
  size_t index = ctx->sz & 0x3f;
  const size_t to_fill = 64 - index;

  ctx->sz += len;

  /* process partial buffer if there's enough data to make a block */
  if (index && len >= to_fill) {
    memcpy(ctx->buf + index, data, to_fill);
    md5_do_chunk(ctx, ctx->buf);
    /* memset(ctx->buf, 0, 64); */
    len -= to_fill;
    data += to_fill;
    index = 0;
  }

  /* process as many 64-blocks as possible */
  while (len >= 64) {
    md5_do_chunk(ctx, data);
    len -= 64;
    data += 64;
  }

  /* append data into buf */
  if (len)
    memcpy(ctx->buf + index, data, len);
}

static inline uint64_t
hs_cryptohash_md5_finalize(struct md5_ctx *ctx, uint8_t *out)
{
  static const uint8_t padding[64] = { 0x80, };
  const uint64_t sz = ctx->sz;

  /* add padding and update data with it */
  const uint64_t bits = cpu_to_le64(ctx->sz << 3);

  /* pad out to 56 */
  const size_t index = (ctx->sz & 0x3f);
  const size_t padlen = (index < 56) ? (56 - index) : ((64 + 56) - index);
  hs_cryptohash_md5_update(ctx, padding, padlen);

  /* append length */
  hs_cryptohash_md5_update(ctx, (const uint8_t *) &bits, sizeof(bits));

  /* output hash */
  cpu_to_le32_array((uint32_t *) out, ctx->h, 4);

  return sz;
}

static inline void
hs_cryptohash_md5_hash (const uint8_t *data, size_t len, uint8_t *out)
{
  struct md5_ctx ctx;

  hs_cryptohash_md5_init(&ctx);

  hs_cryptohash_md5_update(&ctx, data, len);

  hs_cryptohash_md5_finalize(&ctx, out);
}

#endif
