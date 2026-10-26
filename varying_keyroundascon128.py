import os
import time
import statistics
from ascon128 import get_random_bytes, bytes_to_state, to_bytes, rotr

# --- Helper Functions ---
def hamming_weight(n: int) -> int:
    return bin(n).count('1')

def state_distance(S1: list[int], S2: list[int]) -> int:
    return sum(hamming_weight(s1 ^ s2) for s1, s2 in zip(S1, S2))

def flip_single_bit(data: bytes, bit_index: int = 0) -> bytes:
    data_int = int.from_bytes(data, 'big')
    flipped_int = data_int ^ (1 << bit_index)
    return flipped_int.to_bytes(len(data), 'big')

def ascon_single_round(S: list[int], r: int) -> None:
    S[2] ^= (0xf0 - r*0x10 + r*0x1)
    S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
    T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i+1)%5] for i in range(5)]
    for i in range(5): S[i] ^= T[(i+1)%5]
    S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= 0XFFFFFFFFFFFFFFFF
    
    S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
    S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
    S[2] ^= rotr(S[2],  1) ^ rotr(S[2],  6)
    S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
    S[4] ^= rotr(S[4],  7) ^ rotr(S[4], 41)

# --- Initialization with Dynamic Ra and Rb ---
def dynamic_initialize(key: bytes, nonce: bytes, a_rounds: int, b_rounds: int) -> list[int]:
    rate = 8
    key_len_bits = len(key) * 8
    
    # Cap the IV byte at 255 to prevent Python integer overflow
    safe_key_len = min(key_len_bits, 255)
    init_vector = to_bytes([safe_key_len, rate * 8, a_rounds, b_rounds, 0, 0, 0, 0])
    
    state_bytes = init_vector + key
    remaining_space = 40 - len(state_bytes)
    
    if remaining_space > 0:
        state_bytes += nonce[:remaining_space]
        
    return bytes_to_state(state_bytes)

# --- Stage 3 Execution ---
def run_stage3_dynamic_matrix():
    print("===========================================================================")
    print(" STAGE 3: ASCON WITH VARYING KEY SIZES + DYNAMIC ROUNDS (Ra, Rb) ")
    print("===========================================================================")
    print(f"{'Key (bits)':<12} | {'Ra':<4} | {'Rb':<4} | {'Rounds to 50% Diff.':<20} | {'Median Latency (µs)':<20}")
    print("-" * 75)
    
    key_sizes_bytes = [16, 24, 32] # 128-bit, 192-bit, 256-bit
    ra_values = [10, 11, 12, 13]
    rb_values = [6, 8]
    payload = get_random_bytes(64)
    target_diffusion = 160
    
    for k_bytes in key_sizes_bytes:
        k_bits = k_bytes * 8
        base_key = get_random_bytes(k_bytes)
        flipped_key = flip_single_bit(base_key, 0)
        
        for ra in ra_values:
            for rb in rb_values:
                # 1. Diffusion Test (SAC)
                nonce = get_random_bytes(16)
                S_base = dynamic_initialize(base_key, nonce, ra, rb)
                S_flip = dynamic_initialize(flipped_key, nonce, ra, rb)
                
                rounds_to_target = "Failed"
                # We test up to the specified Ra rounds
                for r in range(12 - ra, 12):
                    ascon_single_round(S_base, r)
                    ascon_single_round(S_flip, r)
                    if state_distance(S_base, S_flip) >= target_diffusion:
                        # Count how many rounds it took (1-indexed)
                        rounds_to_target = str(r - (12 - ra) + 1)
                        break
                
                # 2. Latency Benchmark (1000 iterations)
                latencies = []
                for _ in range(1000):
                    iter_nonce = get_random_bytes(16) 
                    start_time = time.perf_counter()
                    
                    _S = dynamic_initialize(base_key, iter_nonce, ra, rb)
                    # Simulate processing the 64-byte payload using Rb rounds
                    for i in range(0, 64, 8):
                        _S[0] ^= int.from_bytes(payload[i:i+8], 'big')
                        for _r in range(12 - rb, 12): 
                            ascon_single_round(_S, _r)
                            
                    end_time = time.perf_counter()
                    latencies.append((end_time - start_time) * 1_000_000)
                
                median_latency = statistics.median(latencies)
                
                # Print the row for this combination
                print(f"{k_bits:<12} | {ra:<4} | {rb:<4} | {rounds_to_target:<20} | {median_latency:.2f}")

if __name__ == "__main__":
    run_stage3_dynamic_matrix()