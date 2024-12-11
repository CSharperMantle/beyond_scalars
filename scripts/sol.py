import itertools as it
import string
import typing as ty

import more_itertools as mit


def u32(x: int) -> int:
    return x & 0xFFFFFFFF


def gen_keystream(
    key: ty.Sequence[int],
    nonce: int,
    init_ctr: int,
    deltas: ty.Sequence[int],
    n_rounds: int,
):
    assert len(deltas) == 4 and len(key) == 4
    n_block = 0
    while True:
        ctr = nonce + init_ctr + n_block
        v0, v1 = u32(ctr), u32(ctr >> 32)
        sum_ = 0
        for _ in range(n_rounds):
            v0 = (
                v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_ + key[sum_ & 3]))
            ) & 0xFFFFFFFF
            sum_ = (sum_ + deltas[n_block % 4]) & 0xFFFFFFFF
            v1 = (
                v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_ + key[(sum_ >> 11) & 3]))
            ) & 0xFFFFFFFF
        block = v0.to_bytes(4, "little") + v1.to_bytes(4, "little")
        for b in block:
            yield b
        n_block += 1


# fmt: off
KEY = [int.from_bytes(b, "little") for b in (mit.chunked(b"hgame-2025@vidar", 4))]
DELTAS = [int.from_bytes(b, "little") for b in (mit.chunked(b"schedule 32b key", 4))]
CRIB = b"hgame{"
CIPHERTEXT = [0x79, 0x95, 0xdd, 0x1a, 0xde, 0x0d, 0x85, 0xaa, 0x52, 0xf2, 0xe4, 0x5f, 0xdf, 0x0f, 0x45, 0x01, 0xe0, 0xf1, 0x83, 0xa7, 0x56, 0x7e, 0xe7, 0xec, 0x52, 0x52, 0xd7, 0x8a, 0x82, 0x09, 0xc3, 0x2b]
ALPHABET = (string.ascii_letters + string.digits + string.punctuation).encode("ascii")
# fmt: on

for comb in it.product(ALPHABET, repeat=8 - len(CRIB)):
    nonce = int.from_bytes(CRIB + bytes(comb), "little")
    try:
        plain = bytes(
            (
                (k ^ c) & 0xFF
                for k, c in zip(gen_keystream(KEY, nonce, 0, DELTAS, 48), CIPHERTEXT)
            )
        ).decode("ascii", errors="strict")
    except:
        continue
    if plain.strip().endswith("}"):
        print(CRIB.decode() + bytes(comb).decode() + plain)
