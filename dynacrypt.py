import math
import os
import psutil
import time
import tracemalloc

# HELPER FUNCTIONS
def get_random_bytes(num: int) -> bytes:
    return to_bytes(os.urandom(num))

def to_bytes(l: bytes|list[int]) -> bytes:
    return bytes(bytearray(l))

def zero_bytes(n: int) -> bytes:
    return n * b"\x00"

def bytes_to_int(bytes: bytes) -> int:
    return sum([bi << (i*8) for i, bi in enumerate(to_bytes(bytes))])

def bytes_to_state(bytes: bytes, length: int) -> list[int]:
    return [bytes_to_int(bytes[8*w:8*(w+1)]) for w in range(length)]

def int_to_bytes(integer: int, nbytes: int) -> bytes:
    return to_bytes([(integer >> (i * 8)) % 256 for i in range(nbytes)])

def rotl(val: int, r: int) -> int:
    return (val << r) | ((val & ((1<<r)-1)) >> (64-r))

def permutate(S: list[int], R: int) -> None:
    # round constant
    for p in range(R):
        S[2] ^= (p * Rc_0) % (2 ** 64)
        T = []

        # Sbox design
        T.append((S[0] | S[1]) & (S[1] | S[2] | S[3]) & (S[1] | S[4] | ~S[3]) & (S[3] | ~S[0] | ~S[1] | ~S[2]) & (~S[0] | ~S[1] | ~S[3] | ~S[4]))
        T.append((S[1] | S[2]) & (S[2] | S[3] | S[4]) & (S[0] | S[2] | ~S[4]) & (S[4] | ~S[1] | ~S[2] | ~S[3]) & (~S[0] | ~S[1] | ~S[2] | ~S[4]))
        T.append((S[2] | S[3]) & (S[0] | S[3] | S[4]) & (S[1] | S[3] | ~S[0]) & (S[0] | ~S[2] | ~S[3] | ~S[4]) & (~S[0] | ~S[1] | ~S[2] | ~S[3]))
        T.append((S[3] | S[4]) & (S[0] | S[1] | S[4]) & (S[2] | S[4] | ~S[1]) & (S[1] | ~S[0] | ~S[3] | ~S[4]) & (~S[1] | ~S[2] | ~S[3] | ~S[4]))
        T.append((S[0] | S[4]) & (S[0] | S[1] | S[2]) & (S[0] | S[3] | ~S[2]) & (S[2] | ~S[0] | ~S[1] | ~S[4]) & (~S[0] | ~S[2] | ~S[3] | ~S[4]))
        #diffusion layer
        S[0] ^= rotl(T[1],  7) ^ rotl(T[2], 41)
        S[1] ^= rotl(T[2], 10) ^ rotl(T[3], 17)
        S[2] ^= rotl(T[3],  1) ^ rotl(T[4],  6)
        S[3] ^= rotl(T[4], 61) ^ rotl(T[0], 39)
        S[4] ^= rotl(T[0], 19) ^ rotl(T[1], 28)

def initialize(key: bytes, nonce: list[int], DS_init: int, R_a: int, rate: int) -> list[int]:
    k = bytes_to_state(key + to_bytes([0x80]) + zero_bytes((rate - (len(key) % rate) - 1)), 5)
    S = k
    S[0] ^= nonce[0]
    S[1] ^= nonce[1]
    S[2] = k[3]
    S[3] = S[0] ^ S[1]
    S[4] = DS_init ^ k[2]

    permutate(S, R_a)
    
    S[0] ^= 0
    S[1] ^= k[0]
    S[2] ^= k[1]
    S[3] ^= k[2]
    S[4] ^= k[3]

    return S

def process_associated_data(S: list[int], associated_data: bytes) -> None:
    if len(associated_data) > 0:
        a_padded = associated_data + to_bytes([0x80]) + zero_bytes((rate - (len(associated_data) % rate) - 1))
        T = []
        for i in S:
            T.append(i)
        for i in range(0, len(a_padded), rate):
            T[0] ^= bytes_to_int(a_padded[i*rate:(i+1)*rate])
            permutate(T, R_b)
            for k in range(len(S)):
                S[k] ^= T[k]
    S[-1] ^= 2

def process_plain_text(S: list[int], plain_text: bytes, R_b: int) -> bytes:
    p_lastlen = len(plain_text) % rate
    p_padding = to_bytes([0x80]) + zero_bytes(rate - p_lastlen - 1)
    p_padded = plain_text + p_padding
    cipherText = bytes([])

    block = 0
    loop = len(plain_text) // rate
    for _ in range(loop):
        S[2] = S[0] ^ bytes_to_int(p_padded[block:block+8])
        cipherText += int_to_bytes(S[2], rate)
        permutate(S, R_b)
        block += rate

    S[2] = S[0] ^ bytes_to_int(p_padded[len(plain_text)-p_lastlen:])
    cipherText += int_to_bytes(S[0] ^ bytes_to_int(p_padded[len(plain_text)-p_lastlen:]), rate)

    return cipherText[:len(plain_text)]

def process_cipher_text(S: list[int], cipher_text: bytes, R_b: int) -> bytes:
    c_lastlen = len(cipher_text) % rate
    decipheredText = bytes([])

    block = 0
    loop = len(cipher_text) // rate
    for _ in range(loop):
        decipheredText += int_to_bytes(S[0] ^ bytes_to_int(cipher_text[block:block+8]), 8)
        S[2] = bytes_to_int(cipher_text[block:block+8])
        permutate(S, R_b)
        block += rate

    Pt_tilda = int_to_bytes(bytes_to_int(int_to_bytes(S[0], c_lastlen)) ^ bytes_to_int(cipher_text[len(cipher_text)-c_lastlen:]), c_lastlen)
    Pt = Pt_tilda + to_bytes([0x80]) + zero_bytes(rate - c_lastlen - 1)
    decipheredText += Pt_tilda
    S[2] = S[0] ^ bytes_to_int(Pt)

    return decipheredText[:len(cipher_text)]

def finalize(S: list[int], R_a: int) -> bytes:
    k = bytes_to_state(key, 5)
    S[0] ^= Rc_0
    S[1] ^= k[0]
    S[2] ^= k[1]
    S[3] ^= k[2]
    S[4] ^= k[3]

    permutate(S, R_a)

    skip_len = abs(key_size-16)
    S[3] ^= bytes_to_int(key[skip_len:skip_len+8])
    S[4] ^= bytes_to_int(key[skip_len+8:skip_len+16])
    tag = bytes_to_int(int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8))

    return int_to_bytes(tag, 16)

def encrypt(associated_data: bytes, plain_text: bytes) -> tuple[bytes, bytes]:
    S = initialize(key, nonce, DS_init, R_a, rate)
    process_associated_data(S, associated_data)
    cipher_text = process_plain_text(S, plain_text, R_b)
    tag = finalize(S, R_a)
    # print(f"Cipher text: {cipher_text}, tag: {tag}")
    return cipher_text, tag

def decrypt(cipher_text: bytes, associated_data: bytes) -> bytes:
    S = initialize(key, nonce, DS_init, R_a, rate)
    process_associated_data(S, associated_data)
    plain_text = process_cipher_text(S, cipher_text, R_b)
    tag = finalize(S, R_a)
    # print(f"Decrypted text: {plain_text}, tag: {tag}")
    return tag

def main(associated_data: bytes, plain_text: bytes):
    cipher_text, tag = encrypt(associated_data, plain_text)
    dtag = decrypt(cipher_text, associated_data)
    if tag == dtag:
        print("VERIFICATION SUCCESS!!!")
    else:
        print("VERIFICATION FAILED!!!")

associated_data = ""
plain_text = ""
key_size = 16 + (4 * (len(plain_text) % 5))
key = get_random_bytes(key_size)
R_a = 12 + math.floor((key_size - 16) / 8)
R_b = R_a - 6
nonce = bytes_to_state(get_random_bytes(16), 2)
rate = 8
DS_init = 1 << 63
Rc_0 = 11400714819323197440

def run_test(associatedData: str, plainText: str):
    global associated_data, plain_text, key_size, key, R_a, R_b
    key_size = 16 + (4 * (len(plain_text) % 5))
    key = get_random_bytes(key_size)
    R_a = 12 + math.floor((key_size - 16) / 8)
    R_b = R_a - 6

    associated_data = associatedData.encode("utf-8")
    plain_text = plainText.encode("utf-8")

    process = psutil.Process(os.getpid())

    tracemalloc.start()
    start_time = time.perf_counter()
    start_cpu = process.cpu_times()
    start_mem = process.memory_info().rss

    main(associated_data, plain_text)

    end_time = time.perf_counter()
    end_cpu = process.cpu_times()
    end_mem = process.memory_info().rss
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "test_string": plainText,
        "bits": len(plainText.encode("utf-8")) * 8,
        "cpu_usage": (end_cpu.user - start_cpu.user) +
                     (end_cpu.system - start_cpu.system),
        "memory_usage": peak / 1024,   # KB
        "time_taken": end_time - start_time
    }

if __name__ == "__main__":
    process = psutil.Process(os.getpid())

    # Start measuring
    tracemalloc.start()
    start_time = time.perf_counter()
    start_cpu = process.cpu_times()
    start_mem = process.memory_info().rss

    # main()

    # Stop measuring
    end_time = time.perf_counter()
    end_cpu = process.cpu_times()
    end_mem = process.memory_info().rss
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print("\n===== PERFORMANCE METRICS =====")
    print(f"key size: {len(key)}")
    print(f"Ra: {R_a}")
    print(f"Rb: {R_b}")
    print(f"Execution Time: {end_time - start_time:.6f} seconds")
    print(f"CPU User Time: {end_cpu.user - start_cpu.user:.6f} seconds")
    print(f"CPU System Time: {end_cpu.system - start_cpu.system:.6f} seconds")
    print(f"Memory Usage Start: {start_mem / (1024 ** 2):.3f} MB")
    print(f"Memory Usage End: {end_mem / (1024 ** 2):.3f} MB")
    print(f"Memory Allocated (current): {current / 1024:.2f} KB")
    print(f"Memory Peak (during run): {peak / 1024:.2f} KB")