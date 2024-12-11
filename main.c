#define _CRT_SECURE_NO_WARNINGS

#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>

#pragma warning(push)
#pragma warning(disable : 6031)
#pragma warning(disable : 4295)

// https://stackoverflow.com/questions/1113409/attribute-constructor-equivalent-in-vc
#ifdef __cplusplus
#define INITIALIZER(f) \
        static void f(void); \
        struct f##_t_ { f##_t_(void) { f(); } }; static f##_t_ f##_; \
        static void f(void)
#elif defined(_MSC_VER)
#pragma section(".CRT$XCU",read)
#define INITIALIZER2_(f,p) \
        static void f(void); \
        __declspec(allocate(".CRT$XCU")) void (*f##_)(void) = f; \
        __pragma(comment(linker,"/include:" p #f "_")) \
        static void f(void)
#ifdef _WIN64
#define INITIALIZER(f) INITIALIZER2_(f,"")
#else
#define INITIALIZER(f) INITIALIZER2_(f,"_")
#endif
#else
#define INITIALIZER(f) \
        static void f(void) __attribute__((constructor)); \
        static void f(void)
#endif

static uint8_t XOR_TABLE[256][256] = {0};

INITIALIZER(init_make_table) {
    for (size_t i = 0; i < 256; i++) {
        for (size_t j = 0; j < 256; j++) {
            XOR_TABLE[i][j] = (uint8_t)i ^ (uint8_t)j;
        }
    }
}

static uint32_t bit_binop_u32(uint32_t a, uint32_t b, const uint8_t table[256][256]) {
    uint32_t v = 0;
    for (size_t i = 0; i < sizeof(uint32_t); i++) {
        v |= table[(a >> (i * 8)) & 0xff][(b >> (i * 8)) & 0xff] << (i * 8);
    }
    return v;
}

static __declspec(noinline) void xtea_enc_256b(const uint32_t v[8], const uint32_t k[4], uint32_t out[8], size_t n_rounds) {
    static _Alignas(16) const char DELTA_STR[17] = "schedule 32b key";

    const __m128i DELTA = _mm_loadu_si128((__m128i *)DELTA_STR);
    __m256i v_ = _mm256_loadu_si256((const __m256i *)v);
    v_ = _mm256_permutevar8x32_epi32(v_, _mm256_set_epi32(7, 5, 3, 1, 6, 4, 2, 0));
    __m128i v0 = _mm256_extracti128_si256(v_, 0);
    __m128i v1 = _mm256_extracti128_si256(v_, 1);
    __m128i sum = _mm_setzero_si128();
    for (size_t i = 0; i < n_rounds; i++) {
        v0 = _mm_add_epi32(v0,
            _mm_xor_epi32(
                _mm_add_epi32(
                    _mm_xor_epi32(
                        _mm_slli_epi32(v1, 4),
                        _mm_srli_epi32(v1, 5)),
                    v1),
                _mm_add_epi32(
                    sum,
                    _mm_i32gather_epi32(
                        k,
                        _mm_and_epi32(
                            sum,
                            _mm_set_epi32(3, 3, 3, 3)),
                        4))));
        sum = _mm_add_epi32(sum, DELTA);
        v1 = _mm_add_epi32(v1,
            _mm_xor_epi32(
                _mm_add_epi32(
                    _mm_xor_epi32(
                        _mm_slli_epi32(v0, 4),
                        _mm_srli_epi32(v0, 5)),
                    v0),
                _mm_add_epi32(
                    sum,
                    _mm_i32gather_epi32(
                        k,
                        _mm_and_epi32(
                            _mm_srli_epi32(sum, 11),
                            _mm_set_epi32(3, 3, 3, 3)),
                        4))));
    }
    v_ = _mm256_set_m128i(v1, v0);
    v_ = _mm256_permutevar8x32_epi32(v_, _mm256_set_epi32(7, 3, 6, 2, 5, 1, 4, 0));
    _mm256_storeu_si256((__m256i *)out, v_);
}

static __declspec(noinline) void xtea_ctr_enc(const uint32_t *msg,
    const uint32_t *key,
    uint64_t nonce,
    size_t n_rounds,
    uint32_t *out,
    size_t len) {
    assert(len % (8 * sizeof(uint32_t)) == 0);

    for (uint64_t i = 0; i < len / (8 * sizeof(uint32_t)); i++) {
        uint64_t xtea_input[4];
        uint32_t xtea_output[8];
        for (size_t j = 0; j < 4; j++) {
            xtea_input[j] = nonce + i * 4 + j;
        }
        xtea_enc_256b(xtea_input, key, xtea_output, n_rounds);
        for (size_t j = 0; j < 8; j++) {
            out[8 * i + j] = bit_binop_u32(msg[8 * i + j], xtea_output[j], XOR_TABLE);
        }
    }
}

static const uint8_t KEY[4][4] = {"hgam", "e-20", "25@v", "idar"};

// hgame{X86_SIMD_1nstruct1on5_4r3_awes0m3}

static const uint8_t TARGET[32] = {
    0x79, 0x95, 0xdd, 0x1a, 0xde, 0x0d, 0x85, 0xaa, 0x52, 0xf2, 0xe4, 0x5f, 0xdf, 0x0f, 0x45, 0x01, 0xe0, 0xf1, 0x83, 0xa7, 0x56, 0x7e, 0xe7, 0xec, 0x52, 0x52, 0xd7, 0x8a, 0x82, 0x09, 0xc3, 0x2b
};

int main(void) {
    char input[48] = {0};
    scanf("%40s", input);

    uint8_t out[sizeof TARGET] = {0};
    xtea_ctr_enc(&input[8], KEY, *((uint64_t *)&input[0]), 48, out, sizeof TARGET);

    if (!memcmp(out, TARGET, sizeof TARGET)) {
        puts("Good!");
    } else {
        puts("Try again.");
#ifdef CSMANTLE
        for (size_t i = 0; i < sizeof out; i++) {
            printf("0x%02hhx, ", ((uint8_t *)out)[i]);
        }
        putchar('\n');
#endif
    }

    return 0;
}

#pragma warning(pop)
