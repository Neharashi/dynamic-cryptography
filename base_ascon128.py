import os
import time
import statistics
import copy
from ascon128 import get_random_bytes, bytes_to_state, to_bytes, rotr, ascon_encrypt

# --- Helper Functions for SAC Testing ---
def hamming_weight(n: int) -> int:
    """Calculates the number of set bits (1s)."""
    return bin(n).count('1')

def state_distance(S1: list[int], S2: list[int]) -> int:
    """Calculates the total Hamming distance between two 320-bit states."""
    return sum(hamming_weight(s1 ^ s2) for s1, s2 in zip(S1, S2))

def flip_single_bit(data: bytes, bit_index: int = 0) -> bytes:
    """Flips a specific bit in a byte array."""
    data_int = int.from_bytes(data, 'big')
    flipped_int = data_int ^ (1 << bit_index)
    return flipped_int.to_bytes(len(data), 'big')

def ascon_single_round(S: list[int], r: int) -> None:
    """Executes exactly one round of the Ascon permutation."""
    # Round constant addition
    S[2] ^= (0xf0 - r*0x10 + r*0x1)
    
    # Substitution layer
    S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
    T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i+1)%5] for i in range(5)]
    for i in range(5): S[i] ^= T[(i+1)%5]
    S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= 0XFFFFFFFFFFFFFFFF
    
    # Linear diffusion layer
    S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
    S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
    S[2] ^= rotr(S[2],  1) ^ rotr(S[2],  6)
    S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
    S[4] ^= rotr(S[4],  7) ^ rotr(S[4], 41)

# --- Stage 1: The Baseline ---
def run_stage1_baseline():
    print("==================================================")
    print("STAGE 1: STANDARD ASCON-128 BASELINE")
    print("==================================================")
    
    # 1. Configuration
    key_size = 16 # 128 bits
    rate = 8
    a_rounds = 12
    b_rounds = 6
    version = 1 # Ascon-AEAD128
    
    # Generate Base Data
    base_key = get_random_bytes(key_size)
    nonce = get_random_bytes(16)
    
    # Generate Flipped Key (Flipping the least significant bit)
    flipped_key = flip_single_bit(base_key, 0)

    # 2. Initialization & SAC Tracking
    print("\n--- Avalanche Effect (Diffusion) Test ---")
    # Formulate the IV exactly as in ascon128.py
    init_vector = to_bytes([key_size * 8, rate * 8, a_rounds, b_rounds, 0, 0, 0, 0])
    
    # Load initial states
    S_base = bytes_to_state(init_vector + base_key + nonce)
    S_flip = bytes_to_state(init_vector + flipped_key + nonce)
    
    distances = []
    target_diffusion = 160 # 50% of 320 bits
    rounds_to_target = None
    
    print(f"Initial State Distance (Pre-Permutation): {state_distance(S_base, S_flip)} bits")
    
    # Execute the 12 rounds step-by-step
    for r in range(12 - a_rounds, 12):
        ascon_single_round(S_base, r)
        ascon_single_round(S_flip, r)
        
        dist = state_distance(S_base, S_flip)
        distances.append(dist)
        print(f"Round {r+1} Distance: {dist} bits")
        
        if dist >= target_diffusion and rounds_to_target is None:
            rounds_to_target = r + 1
            
    if rounds_to_target:
        print(f"-> 50% Diffusion (>= 160 bits) achieved at Round {rounds_to_target}")
    else:
        print("-> 50% Diffusion NOT achieved within standard rounds!")

    # 3. Execution Latency Test
    print("\n--- Latency Benchmark (64-byte payload, 1000 iterations) ---")
    payload = get_random_bytes(64)
    ad = get_random_bytes(16)
    
    latencies = []
    for _ in range(1000):
        # Fresh nonce for each encryption to prevent caching anomalies
        iter_nonce = get_random_bytes(16) 
        
        start_time = time.perf_counter()
        _ = ascon_encrypt(base_key, iter_nonce, ad, payload, "Ascon-AEAD128")
        end_time = time.perf_counter()
        
        # Convert to microseconds
        latencies.append((end_time - start_time) * 1_000_000) 
        
    avg_latency = statistics.mean(latencies)
    median_latency = statistics.median(latencies)
    
    print(f"Average Execution Time: {avg_latency:.2f} µs")
    print(f"Median Execution Time:  {median_latency:.2f} µs")
    print("==================================================\n")

if __name__ == "__main__":
    run_stage1_baseline()