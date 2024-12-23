#ifndef CHACHA_H_INCLUDED_
#define CHACHA_H_INCLUDED_

#include <stdint.h>
#include <intrin.h>

#ifndef CHACHA_ROUNDS
#define CHACHA_ROUNDS 20
#endif

extern uint8_t CHACHA_TAU[16];

void chacha20_enc(uint8_t const key[32], uint8_t const nonce[12], uint32_t counter, uint8_t const *buf_in, size_t in_len, uint8_t *buf_out);

#ifdef CSMANTLE
void test_chacha20_qr(void);
void test_chacha20_block(void);
void test_chacha20_enc(void);
#endif /* CSMANTLE */

#endif /* CHACHA_H_INCLUDED_ */
