#include "chacha.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

static inline __m128i rolv(__m128i v, __m128i shamt) {
    return _mm_or_si128(_mm_sllv_epi32(v, shamt), _mm_srlv_epi32(v, _mm_sub_epi32(_mm_set1_epi32(32), shamt)));
}

static inline __m128i roli(__m128i v, int shamt) {
    return _mm_or_si128(_mm_slli_epi32(v, shamt), _mm_srli_epi32(v, 32 - shamt));
}

#define QR_(va_, vb_, vc_, vd_) \
    do { \
        va_ = _mm_add_epi32(va_, vb_); vd_ = _mm_xor_si128(vd_, va_); vd_ = roli(vd_, 16); \
        vc_ = _mm_add_epi32(vc_, vd_); vb_ = _mm_xor_si128(vb_, vc_); vb_ = roli(vb_, 12); \
        va_ = _mm_add_epi32(va_, vb_); vd_ = _mm_xor_si128(vd_, va_); vd_ = roli(vd_, 8); \
        vc_ = _mm_add_epi32(vc_, vd_); vb_ = _mm_xor_si128(vb_, vc_); vb_ = roli(vb_, 7); \
    } while (0)

static void chacha20_block(uint32_t const buf_in[16], uint32_t buf_out[16]) {
    __m128i x0, x1, x2, x3, v0, v1, v2, v3;
    x0 = v0 = _mm_loadu_epi32(buf_in);
    x1 = v1 = _mm_loadu_epi32(buf_in + 4);
    x2 = v2 = _mm_loadu_epi32(buf_in + 8);
    x3 = v3 = _mm_loadu_epi32(buf_in + 12);

    for (size_t i = 0; i < CHACHA_ROUNDS; i += 2) {
        QR_(v0, v1, v2, v3);
        v0 = _mm_shuffle_epi32(v0, _MM_SHUFFLE(3, 2, 1, 0));
        v1 = _mm_shuffle_epi32(v1, _MM_SHUFFLE(0, 3, 2, 1));
        v2 = _mm_shuffle_epi32(v2, _MM_SHUFFLE(1, 0, 3, 2));
        v3 = _mm_shuffle_epi32(v3, _MM_SHUFFLE(2, 1, 0, 3));
        QR_(v0, v1, v2, v3);
        v0 = _mm_shuffle_epi32(v0, _MM_SHUFFLE(3, 2, 1, 0));
        v1 = _mm_shuffle_epi32(v1, _MM_SHUFFLE(2, 1, 0, 3));
        v2 = _mm_shuffle_epi32(v2, _MM_SHUFFLE(1, 0, 3, 2));
        v3 = _mm_shuffle_epi32(v3, _MM_SHUFFLE(0, 3, 2, 1));
    }

    _mm_storeu_epi32(buf_out, _mm_add_epi32(x0, v0));
    _mm_storeu_epi32(buf_out + 4, _mm_add_epi32(x1, v1));
    _mm_storeu_epi32(buf_out + 8, _mm_add_epi32(x2, v2));
    _mm_storeu_epi32(buf_out + 12, _mm_add_epi32(x3, v3));
}

void chacha20_enc(uint8_t const key[32], uint8_t const nonce[12], uint32_t counter, uint8_t const *buf_in, size_t in_len, uint8_t *buf_out) {
    union u {
        uint32_t as_u32_buf[16];
        uint8_t as_u8_buf[64];
        struct {
            uint8_t tau[16];
            uint8_t key[32];
            uint32_t counter;
            uint8_t nonce[12];
        };
    } x = {0}, y = {0};
    for (size_t j = 0; j < in_len / 64; j++) {
        memcpy(x.tau, CHACHA_TAU, sizeof x.tau);
        memcpy(x.key, key, 32);
        x.counter = counter + j;
        memcpy(x.nonce, nonce, 12);
        chacha20_block(x.as_u32_buf, y.as_u32_buf);
        for (size_t i = 0; i < 64 / sizeof(__m128i); i++) {
            _mm_storeu_epi32(
                &buf_out[j * 64 + i * sizeof(__m128i)],
                _mm_xor_epi32(
                    _mm_loadu_epi32(&buf_in[j * 64 + i * sizeof(__m128i)]),
                    _mm_loadu_epi32(&y.as_u32_buf[i * (sizeof(__m128i) / sizeof(uint32_t))])
                )
            );
        }
    }
    size_t rem = in_len % 64;
    if (rem != 0) {
        size_t j = in_len / 64;
        memcpy(x.tau, CHACHA_TAU, sizeof x.tau);
        memcpy(x.key, key, 32);
        x.counter = counter + j;
        memcpy(x.nonce, nonce, 12);
        chacha20_block(x.as_u32_buf, y.as_u32_buf);
        for (size_t i = 0; i < rem; i++) {
            buf_out[j * 64 + i] = buf_in[j * 64 + i] ^ y.as_u8_buf[i];
        }
    }
}

#ifdef CSMANTLE
void test_chacha20_qr(void) {
    __m128i a, b, c, d;
    a = _mm_set1_epi32(0x11111111);
    b = _mm_set1_epi32(0x01020304);
    c = _mm_set1_epi32(0x9b8d6f43);
    d = _mm_set1_epi32(0x01234567);
    QR_(a, b, c, d);
    assert(_mm_movemask_epi8(_mm_cmpeq_epi32(a, _mm_set1_epi32(0xea2a92f4))) == 0xffff);
    assert(_mm_movemask_epi8(_mm_cmpeq_epi32(b, _mm_set1_epi32(0xcb1cf8ce))) == 0xffff);
    assert(_mm_movemask_epi8(_mm_cmpeq_epi32(c, _mm_set1_epi32(0x4581472e))) == 0xffff);
    assert(_mm_movemask_epi8(_mm_cmpeq_epi32(d, _mm_set1_epi32(0x5881c4bb))) == 0xffff);
}

void test_chacha20_block(void) {
    static const uint32_t X[16] = {
       0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
       0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
       0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
       0x00000001, 0x09000000, 0x4a000000, 0x00000000,
    };
    static const uint32_t TARGET[16] = {
       0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
       0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
       0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
       0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
    };
    uint32_t y[16];
    chacha20_block(X, y);
    assert(memcmp(TARGET, y, sizeof(TARGET)) == 0);
}

void test_chacha20_enc(void) {
    static const uint8_t KEY[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t NONCE[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,
    };
    static const uint32_t COUNTER = 1;
    static const uint8_t PLAINTEXT[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    uint8_t y[sizeof PLAINTEXT] = {0};
    static const uint8_t TARGET[] = {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    };
    chacha20_enc(KEY, NONCE, COUNTER, PLAINTEXT, strlen(PLAINTEXT), y);
    assert(memcmp(y, TARGET, sizeof TARGET) == 0);
}
#endif /* CSMANTLE */
