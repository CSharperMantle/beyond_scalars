#define _CRT_SECURE_NO_WARNINGS

#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>

#include "chacha.h"

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

// hgame{X86_SIMD_1nstruct1on5_4r3_awes0m3}

static const uint8_t TARGET[] = {
    0x74, 0xeb, 0xf5, 0x30, 0x07, 0xb6, 0x1e, 0x62,
    0x25, 0x33, 0x5b, 0xce, 0x88, 0x8b, 0xa4, 0x10,
    0x2c, 0xee, 0x69, 0x56, 0x42, 0x6f, 0x2e, 0xc7,
    0xf4, 0xe4, 0xcf, 0x0b, 0xee, 0x05, 0xce, 0xa0,
    0xa2, 0x8e, 0x16, 0x71, 0x3b, 0x61, 0xe2, 0x22,
    0xbc, 0x58, 0x6f, 0x3c, 0x79, 0xb7, 0xc3, 0x99,
    0x74, 0xd0, 0x1a, 0xae, 0xb7, 0x3f, 0xa1, 0xec,
    0x18, 0xae, 0xe6, 0x87, 0x84, 0x2b, 0xce, 0x3d,
};

uint8_t CHACHA_TAU[16] = "WELCOME TO HGAME";

INITIALIZER(ctor_chacha_tau) {
    _mm_storeu_epi32(CHACHA_TAU, _mm_xor_epi32(_mm_loadu_epi32(CHACHA_TAU), _mm_loadu_epi32("\x32\x3d\x3c\x22\x21\x29\x65\x13\x66\x62\x42\x31\x33\x24\x6d\x2e")));
}

int main(void) {
#ifdef CSMANTLE
    test_chacha20_qr();
    test_chacha20_block();
    test_chacha20_enc();
#endif /* CSMANTLE */

    char input[64] = {0};
    uint8_t output[64] = {0};
    scanf("%63s", input);
    size_t len = strlen(input);
    if (len <= 7 || input[5] != '{' || input[len - 1] != '}') {
        puts("Wrong...");
        return 1;
    }
    chacha20_enc("hgame2025-reveng-chal@vidar.club", "simdsimdsimd", *((uint32_t *)input), input, len, output);
    if (memcmp(TARGET, output, len) == 0) {
        puts("Good!");
    } else {
        puts("Wrong...");
#ifdef CSMANTLE
        for (size_t i = 0; i < sizeof output; i++) {
            if (i % 8 == 0) {
                putchar('\n');
            }
            printf("0x%02hhx, ", output[i]);
        }
        putchar('\n');
#endif
    }
    return 0;
}

#pragma warning(pop)
