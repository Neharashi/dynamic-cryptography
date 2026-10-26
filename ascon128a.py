# ===== HELPER FUNCTIONS =====
import os
import time
import tracemalloc

import psutil


def get_random_bytes(num: int) -> bytes:
    return to_bytes(os.urandom(num))

def zero_bytes(n: int) -> bytes:
    return n * b"\x00"

def to_bytes(l: bytes|list[int]) -> bytes:
    return bytes(bytearray(l))

def bytes_to_int(bytes: bytes) -> int:
    return sum([bi << (i*8) for i, bi in enumerate(to_bytes(bytes))])

def bytes_to_state(bytes: bytes) -> list[int]:
    return [bytes_to_int(bytes[8*w:8*(w+1)]) for w in range(5)]

def int_to_bytes(integer: int, nbytes: int) -> bytes:
    return to_bytes([(integer >> (i * 8)) % 256 for i in range(nbytes)])

def rotr(val: int, r: int) -> int:
    return (val >> r) | ((val & (1<<r)-1) << (64-r))

def printstate(S: list[int], description: str="") -> None:
    print("" + description)
    print("  ".join(["{s:016x}".format(s=s) for s in S]))

def printwords(S: list[int], description: str="") -> None:
    print("" + description)
    print("  ".join([f"x{i}={s:016x}" for i, s in enumerate(S)]))


# ===== ASCON FUNCTIONS =====
def ascon_permutation(S: list[int], stage: str, rounds: int = 1) -> None:
    if debugPermutation: printwords(S, f"[{stage}] permutation input:")

    for r in range(12-rounds, 12):
        S[2] ^= (0xf0 - r*0x10 + r*0x1)
        if debugPermutation: printwords(S, f"[{stage}] round {r+1} constant addition:")
        # --- substitution layer ---
        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]
        T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i+1)%5] for i in range(5)]
        for i in range(5):
            S[i] ^= T[(i+1)%5]
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= 0XFFFFFFFFFFFFFFFF
        if debugPermutation: printwords(S, f"[{stage}] round {r+1} substitution layer:")
        # --- linear diffusion layer ---
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2],  1) ^ rotr(S[2],  6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4],  7) ^ rotr(S[4], 41)
        if debugPermutation: printwords(S, f"[{stage}] round {r+1} linear diffusion layer:")

def ascon_initialize(S: list[int], rate: int, a: int, b: int, key: bytes, nonce: bytes, stage: str) -> None:
    init_vector = to_bytes([len(key) * 8, rate * 8, a, b, 0, 0, 0, 0])

    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(init_vector + key + nonce)
    ascon_permutation(S, stage, a)
    zero_key = bytes_to_state(zero_bytes(40-len(key)) + key)
    S[0] ^= zero_key[0]
    S[1] ^= zero_key[1]
    S[2] ^= zero_key[2]
    S[3] ^= zero_key[3]
    S[4] ^= zero_key[4]
    if debug:
        print(f"[{stage}] Initialization Vector:\n"+"".join(["{s:02x}".format(s=s) for s in init_vector]))
        printwords(S, f"[{stage}] Initial State:")

def ascon_process_associated_data(S: list[int], b: int, rate: int, associatedData: bytes, stage: str):
    if len(associatedData) > 0:
        a_padding = to_bytes([0x80]) + zero_bytes((rate - (len(associatedData) % rate) - 1))
        a_padded = associatedData + a_padding

        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block*8:(block+1)*8])
            S[1] ^= bytes_to_int(a_padded[(block+1)*8:(block+2)*8])
            ascon_permutation(S, "ENCRYPTION", b)
    S[4] ^= 1

    if debug: printstate(S, f"[{stage}] processed associated data:")

def ascon_process_plainText(S: list[int], b: int, rate: int, plainText: bytes, stage: str) -> bytes:
    p_lastlen = len(plainText) % rate
    p_padding = to_bytes([0x80]) + zero_bytes(rate - p_lastlen - 1)
    p_padded = plainText + p_padding
    cipherText = bytes([])
    block = 0
    loop = len(plainText) // rate
    for _ in range(loop):
        S[0] ^= bytes_to_int(p_padded[block:block+8])
        S[1] ^= bytes_to_int(p_padded[block+8:block+16])
        cipherText += int_to_bytes(S[0], 8)
        cipherText += int_to_bytes(S[1], 8)
        ascon_permutation(S, "ENCRYPTION", b)
        block += rate
    cipherText += int_to_bytes(S[0] ^ bytes_to_int(p_padded[len(plainText)-p_lastlen:len(plainText)-p_lastlen+8]), 8)
    cipherText += int_to_bytes(S[1] ^ bytes_to_int(p_padded[len(plainText)-p_lastlen+8:]), 8)
    S[0] ^= bytes_to_int(p_padded[len(plainText)-p_lastlen:len(plainText)-p_lastlen+8])
    S[1] ^= bytes_to_int(p_padded[len(plainText)-p_lastlen+8:])
    
    if debug:
        print(f"[{stage}] actual plain text:\n{plainText} and len {len(plainText)} bytes")
        print(f"[{stage}] full cipher text:\n{cipherText} and len {len(cipherText)} bytes")
        print(f"[{stage}] truncated cipher text:\n{cipherText[:len(plainText)]} and len {len(cipherText[:len(plainText)])} bytes")
        printwords(S, f"[{stage}] state after plain text processing:")
    return cipherText[:len(plainText)]

def ascon_process_cipherText(S: list[int], b: int, rate: int, cipherText: bytes, stage: str):
    c_lastlen = len(cipherText) % rate
    decipheredText = bytes([])
    block = 0
    loop = len(cipherText) // rate
    for _ in range(loop):
        decipheredText += int_to_bytes(S[0] ^ bytes_to_int(cipherText[block:block+8]), 8)
        decipheredText += int_to_bytes(S[1] ^ bytes_to_int(cipherText[block+8:block+16]), 8)
        S[0] = bytes_to_int(cipherText[block:block+8])
        S[1] = bytes_to_int(cipherText[block+8:block+16])
        ascon_permutation(S, "DECRYPTION", b)
        block += rate
    if c_lastlen > 8:
        Pt_tilda = int_to_bytes(bytes_to_int(int_to_bytes(S[0], 8)) ^ bytes_to_int(cipherText[len(cipherText)-c_lastlen:len(cipherText)-c_lastlen+8]), 8)
        Pt_tilda += int_to_bytes(bytes_to_int(int_to_bytes(S[1], c_lastlen-8)) ^ bytes_to_int(cipherText[len(cipherText)-c_lastlen+8:]), c_lastlen-8)
    else:
        Pt_tilda = int_to_bytes(bytes_to_int(int_to_bytes(S[0], c_lastlen)) ^ bytes_to_int(cipherText[len(cipherText)-c_lastlen:]), c_lastlen)
    Pt = Pt_tilda + to_bytes([0x80]) + zero_bytes(rate - c_lastlen - 1)
    decipheredText += Pt_tilda
    S[0] ^= bytes_to_int(Pt[0:8])
    S[1] ^= bytes_to_int(Pt[8:16])

    if debug:
        printwords(S, f"[{stage}] state after cipher text processing:")
        print(f"[{stage}] deciphered text:\n{decipheredText} and len {len(decipheredText)} bytes")
    
    return decipheredText[:len(cipherText)]

def ascon_finalize(S: list[int], rate: int, a: int, key: bytes, stage: str):
    S[2] ^= bytes_to_int(key[0:8])
    S[3] ^= bytes_to_int(key[8:16])

    ascon_permutation(S, stage, a)

    S[3] ^= bytes_to_int(key[0:8])
    S[4] ^= bytes_to_int(key[8:16])
    tag = bytes_to_int(int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8))

    if debug:
        printwords(S, f"[{stage}] finalization:")

    return int_to_bytes(tag, 16)


# ===== ENCRYPTION AND DECRYPTION =====
def ascon_encrypt(key: bytes, nonce: bytes, associatedData: bytes, plainText: bytes, variant: str="Ascon-AEAD128"):
    stage = "ENCRYPTION"
    S = [0, 0, 0, 0, 0] # State
    # k = len(key) * 8    # bits
    # a = 12              # permutation rounds
    # b = 6               # permutation rounds

    ascon_initialize(S, rate, a, b, key, nonce, stage)
    ascon_process_associated_data(S, b, rate, associatedData, stage)
    cipherText = ascon_process_plainText(S, b, rate, plainText, stage)
    tag = ascon_finalize(S, rate, a, key, stage)
    encrypted = [cipherText, tag]
    return encrypted

def ascon_decrypt(key: bytes, nonce: bytes, associatedData: bytes, cipherText: bytes, variant: str="Ascon-AEAD128"):
    stage = "DECRYPTION"
    S = [0, 0, 0, 0, 0] # State
    # k = len(key) * 8    # bits
    # a = 12              # permutation rounds
    # b = 6               # permutation rounds

    ascon_initialize(S, rate, a, b, key, nonce, stage)
    ascon_process_associated_data(S, b, rate, associatedData, stage)
    plainText = ascon_process_cipherText(S, b, rate, cipherText, stage)
    tag = ascon_finalize(S, rate, a, key, stage)
    decrypted = [plainText, tag]
    return decrypted


# ===== ASCON AEAD =====
def demo_aead(associatedData: bytes, plainText: bytes, variant: str = "Ascon-AEAD128"):
    # print(f"=== {variant} ===")

    key = get_random_bytes(16)
    nonce = get_random_bytes(16)

    cipherText = ascon_encrypt(key, nonce, associatedData, plainText, variant)
    decryptedPlainText = ascon_decrypt(key, nonce, associatedData, cipherText[0], variant)

    if cipherText[1] == decryptedPlainText[1]: print("VERIFICATION SUCCESS!!!")
    else: print("VERIFICATION FAILED!!!")


# ===== VARIABLES =====
versions = {"Ascon-AEAD128": 1, "Ascon-128a": 2, "Ascon-80pq": 3}
key = get_random_bytes(16)      # 16 bytes for Ascon-128 and Ascon-128a, 20 bytes for Ascon-80pq
nonce = get_random_bytes(16)    # 16 bytes
tag_len = 16                    # 16 bytes
rate = 16                       # 8 bytes for Ascon-128 and Ascon-80pq, 16 bytes for Ascon-128a
a = 12                          # 12 permutation rounds
b = 8                           # 6 permutation rounds for Ascon-128 and Ascon-80pq, 8 for Ascon-128a
debug = False
debugPermutation = False
# ad = input("Enter Associated Data: ")
# associatedData = ad.encode("utf-8")
# pt = input("Enter Plain Text: ")
# plainText = pt.encode("utf-8")

def run_test(associated_data: str, plain_text: str):
    associatedData = associated_data.encode("utf-8")
    plainText = plain_text.encode("utf-8")

    process = psutil.Process(os.getpid())

    tracemalloc.start()
    start_time = time.perf_counter()
    start_cpu = process.cpu_times()
    start_mem = process.memory_info().rss

    demo_aead(associatedData, plainText, "Ascon-AEAD128")

    end_time = time.perf_counter()
    end_cpu = process.cpu_times()
    end_mem = process.memory_info().rss
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "test_string": plain_text,
        "bits": len(plain_text.encode("utf-8")) * 8,
        "cpu_usage": (end_cpu.user - start_cpu.user) +
                     (end_cpu.system - start_cpu.system),
        "memory_usage": peak / 1024,   # KB
        "time_taken": end_time - start_time
    }

if __name__ == "__main__":
    ad = input("Enter Associated Data: ")
    associatedData = ad.encode("utf-8")
    pt = input("Enter Plain Text: ")
    plainText = pt.encode("utf-8")

    process = psutil.Process(os.getpid())

    # Start measuring
    tracemalloc.start()
    start_time = time.perf_counter()
    start_cpu = process.cpu_times()
    start_mem = process.memory_info().rss

    # demo_aead("Ascon-AEAD128")

    # Stop measuring
    end_time = time.perf_counter()
    end_cpu = process.cpu_times()
    end_mem = process.memory_info().rss
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print("\n===== PERFORMANCE METRICS =====")
    print(f"key size: {len(key)}")
    print(f"Ra: {a}")
    print(f"Rb: {b}")
    print(f"Execution Time: {end_time - start_time:.6f} seconds")
    print(f"CPU User Time: {end_cpu.user - start_cpu.user:.6f} seconds")
    print(f"CPU System Time: {end_cpu.system - start_cpu.system:.6f} seconds")
    print(f"Memory Usage Start: {start_mem / (1024 ** 2):.3f} MB")
    print(f"Memory Usage End: {end_mem / (1024 ** 2):.3f} MB")
    print(f"Memory Allocated (current): {current / 1024:.2f} KB")
    print(f"Memory Peak (during run): {peak / 1024:.2f} KB")
