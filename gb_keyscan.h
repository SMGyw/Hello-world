// gb_keyscan.h - pure C, no platform deps. Finds an AES key in a memory buffer by testing every
// candidate window against a known CBC ciphertext whose plaintext is expected to be printable text
// (JSON). Works regardless of the IV: P[i] = D(C[i]) ^ C[i-1] for i >= 1, so blocks 1.. only need
// the ciphertext itself (block 0 acts as the IV / previous block).
#ifndef GB_KEYSCAN_H
#define GB_KEYSCAN_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static uint8_t gb_sbox[256], gb_isbox[256], gb_m9[256], gb_m11[256], gb_m13[256], gb_m14[256];
static int gb_aes_ready = 0;

static uint8_t gb_gm(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) { if (b & 1) p ^= a; uint8_t hi = a & 0x80; a <<= 1; if (hi) a ^= 0x1b; b >>= 1; }
    return p;
}
static uint8_t gb_rotl8(uint8_t x, int s) { return (uint8_t)((x << s) | (x >> (8 - s))); }

static void gb_aes_init(void) {
    if (gb_aes_ready) return;
    uint8_t p = 1, q = 1;
    do {
        p = (uint8_t)(p ^ (uint8_t)(p << 1) ^ ((p & 0x80) ? 0x1B : 0));
        q ^= (uint8_t)(q << 1); q ^= (uint8_t)(q << 2); q ^= (uint8_t)(q << 4);
        if (q & 0x80) q ^= 0x09;
        gb_sbox[p] = (uint8_t)(q ^ gb_rotl8(q, 1) ^ gb_rotl8(q, 2) ^ gb_rotl8(q, 3) ^ gb_rotl8(q, 4) ^ 0x63);
    } while (p != 1);
    gb_sbox[0] = 0x63;
    for (int i = 0; i < 256; i++) gb_isbox[gb_sbox[i]] = (uint8_t)i;
    for (int i = 0; i < 256; i++) {
        gb_m9[i] = gb_gm((uint8_t)i, 9);   gb_m11[i] = gb_gm((uint8_t)i, 11);
        gb_m13[i] = gb_gm((uint8_t)i, 13); gb_m14[i] = gb_gm((uint8_t)i, 14);
    }
    gb_aes_ready = 1;
}

// nk = key words (4 or 8); rk must hold 16*(nk+7) bytes
static void gb_expand(const uint8_t *key, int nk, uint8_t *rk) {
    int nr = nk + 6, total = 4 * (nr + 1);
    memcpy(rk, key, (size_t)(4 * nk));
    uint8_t rcon = 1;
    for (int i = nk; i < total; i++) {
        uint8_t t[4]; memcpy(t, rk + 4 * (i - 1), 4);
        if (i % nk == 0) {
            uint8_t u = t[0];
            t[0] = (uint8_t)(gb_sbox[t[1]] ^ rcon); t[1] = gb_sbox[t[2]]; t[2] = gb_sbox[t[3]]; t[3] = gb_sbox[u];
            rcon = (uint8_t)((rcon << 1) ^ ((rcon & 0x80) ? 0x1b : 0));
        } else if (nk > 6 && i % nk == 4) {
            for (int j = 0; j < 4; j++) t[j] = gb_sbox[t[j]];
        }
        for (int j = 0; j < 4; j++) rk[4 * i + j] = (uint8_t)(rk[4 * (i - nk) + j] ^ t[j]);
    }
}

static void gb_dec_block(const uint8_t *rk, int nr, const uint8_t *in, uint8_t *out) {
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++) s[i] = (uint8_t)(in[i] ^ rk[16 * nr + i]);
    for (int r = nr - 1; r >= 0; r--) {
        for (int c = 0; c < 4; c++) for (int rr = 0; rr < 4; rr++) t[4 * ((c + rr) & 3) + rr] = s[4 * c + rr];
        for (int i = 0; i < 16; i++) s[i] = (uint8_t)(gb_isbox[t[i]] ^ rk[16 * r + i]);
        if (r > 0) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = s[4*c], a1 = s[4*c+1], a2 = s[4*c+2], a3 = s[4*c+3];
                s[4*c]   = (uint8_t)(gb_m14[a0] ^ gb_m11[a1] ^ gb_m13[a2] ^ gb_m9[a3]);
                s[4*c+1] = (uint8_t)(gb_m9[a0]  ^ gb_m14[a1] ^ gb_m11[a2] ^ gb_m13[a3]);
                s[4*c+2] = (uint8_t)(gb_m13[a0] ^ gb_m9[a1]  ^ gb_m14[a2] ^ gb_m11[a3]);
                s[4*c+3] = (uint8_t)(gb_m11[a0] ^ gb_m13[a1] ^ gb_m9[a2]  ^ gb_m14[a3]);
            }
        }
    }
    memcpy(out, s, 16);
}

static int gb_textish(uint8_t c) { return (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t'; }

// ct: ciphertext (block 0 .. n-1), ctlen multiple of 16 and >= 32. Returns 1 if the key decrypts
// blocks 1.. to text. plain_out (optional, >= 16*(ctlen/16-1) bytes) receives P1..Pn-1.
static int gb_try_key(const uint8_t *key, int klen, const uint8_t *ct, size_t ctlen, uint8_t *plain_out) {
    int nk = klen / 4; uint8_t rk[240], d[16], p[16];
    gb_expand(key, nk, rk);
    int nr = nk + 6;
    size_t nb = ctlen / 16;
    for (size_t b = 1; b < nb; b++) {
        gb_dec_block(rk, nr, ct + 16 * b, d);
        int limit = (b + 1 == nb) ? 4 : 16;   // last block holds padding bytes, only check its start
        for (int i = 0; i < 16; i++) p[i] = (uint8_t)(d[i] ^ ct[16 * (b - 1) + i]);
        for (int i = 0; i < limit; i++) if (!gb_textish(p[i])) return 0;
        if (plain_out) memcpy(plain_out + 16 * (b - 1), p, 16);
    }
    return 1;
}

static int gb_hexv(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

typedef void (*gb_hit_fn)(const uint8_t *key, int klen, const char *how, const uint8_t *plain, size_t plen, size_t off, void *ud);

// Scans b[0..n) with the given stride. Tests raw 16/32-byte windows and 32/64-char hex-text windows.
// Returns number of hits.
static int gb_scan_buffer(const uint8_t *b, size_t n, const uint8_t *ct, size_t ctlen, size_t stride, gb_hit_fn hit, void *ud) {
    gb_aes_init();
    int hits = 0; uint8_t plain[256], hk[32];
    size_t plen = (ctlen / 16 - 1) * 16; if (plen > sizeof plain) plen = sizeof plain;
    for (size_t off = 0; off + 16 <= n; off += stride) {
        for (int klen = 16; klen <= 32; klen += 16) {
            if (off + (size_t)klen > n) break;
            int zeros = 0;
            for (int i = 0; i < klen; i++) zeros += (b[off + i] == 0);
            if (zeros > (klen == 16 ? 2 : 3)) continue;
            if (gb_try_key(b + off, klen, ct, ctlen, plain)) { hit(b + off, klen, "raw", plain, plen, off, ud); hits++; }
        }
        for (int hl = 32; hl <= 64; hl += 32) {   // key stored as hex text
            if (off + (size_t)hl > n) break;
            int okhex = 1;
            for (int i = 0; i < hl; i++) if (gb_hexv(b[off + i]) < 0) { okhex = 0; break; }
            if (!okhex) continue;
            for (int i = 0; i < hl / 2; i++) hk[i] = (uint8_t)((gb_hexv(b[off + 2*i]) << 4) | gb_hexv(b[off + 2*i + 1]));
            if (gb_try_key(hk, hl / 2, ct, ctlen, plain)) { hit(hk, hl / 2, "hex-text", plain, plen, off, ud); hits++; }
        }
    }
    return hits;
}
#endif
