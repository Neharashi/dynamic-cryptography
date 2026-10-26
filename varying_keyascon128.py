import os
import time
import statistics
from ascon128 import get_random_bytes, bytes_to_state, to_bytes, rotr

# --- Helper Functions for SAC Testing ---
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

# --- Naive Initialization for Varying Key Sizes ---
def naive_initialize(key: bytes, nonce: bytes, a_rounds: int = 12) -> list[int]:
    rate = 8
    b_rounds = 6
    key_len_bits = len(key) * 8
    
    # FIX: Cap the IV byte at 255 to prevent Python integer overflow
    safe_key_len = min(key_len_bits, 255)
    init_vector = to_bytes([safe_key_len, rate * 8, a_rounds, b_rounds, 0, 0, 0, 0])
    
    # Fill state: IV + Key + remainder filled by Nonce
    state_bytes = init_vector + key
    remaining_space = 40 - len(state_bytes)
    
    if remaining_space > 0:
        state_bytes += nonce[:remaining_space]
        
    return bytes_to_state(state_bytes)

# --- Stage 2 Execution ---
def run_stage2_varying_keys():
    print("==================================================")
    print("STAGE 2: ASCON WITH VARYING KEY SIZES (NAIVE)")
    print("==================================================")
    
    key_sizes_bytes = [16, 24, 32] # 128-bit, 192-bit, 256-bit
    
    for k_bytes in key_sizes_bytes:
        k_bits = k_bytes * 8
        print(f"\n>>> TESTING KEY SIZE: {k_bits}-bit <<<")
        
        base_key = get_random_bytes(k_bytes)
        nonce = get_random_bytes(16)
        flipped_key = flip_single_bit(base_key, 0)
        
        S_base = naive_initialize(base_key, nonce)
        S_flip = naive_initialize(flipped_key, nonce)
        
        print("--- Avalanche Effect (Diffusion) Test ---")
        print(f"Initial State Distance (Pre-Permutation): {state_distance(S_base, S_flip)} bits")
        
        target_diffusion = 160
        rounds_to_target = None
        
        for r in range(12 - 12, 12):
            ascon_single_round(S_base, r)
            ascon_single_round(S_flip, r)
            dist = state_distance(S_base, S_flip)
            
            # Print the round-by-round metrics
            print(f"Round {r+1} Distance: {dist} bits")
            
            if dist >= target_diffusion and rounds_to_target is None:
                rounds_to_target = r + 1
                
        if rounds_to_target:
            print(f"-> 50% Diffusion (>= 160 bits) achieved at Round {rounds_to_target}")
        else:
            print(f"-> 50% Diffusion NOT achieved in 12 rounds! (Max distance: {dist})")

        print("\n--- Latency Benchmark (64-byte payload) ---")
        payload = get_random_bytes(64)
        latencies = []
        
        for _ in range(1000):
            iter_nonce = get_random_bytes(16) 
            start_time = time.perf_counter()
            _S = naive_initialize(base_key, iter_nonce)
            for i in range(0, 64, 8):
                _S[0] ^= int.from_bytes(payload[i:i+8], 'big')
                for _r in range(12 - 6, 12): ascon_single_round(_S, _r)
            end_time = time.perf_counter()
            latencies.append((end_time - start_time) * 1_000_000)
            
        print(f"Median Execution Time: {statistics.median(latencies):.2f} µs")
        print("-" * 50)

if __name__ == "__main__":
    run_stage2_varying_keys()