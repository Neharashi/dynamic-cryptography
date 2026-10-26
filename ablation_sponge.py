import os
import time
import statistics

# Import your actual algorithm and helper functions
from sponge import acalc_encrypt, get_random_bytes, bytes_to_int, rotr, ROTATION_STD, ROTATION_CRIT

# --- Helper Functions for SAC Testing ---
def hamming_weight(n: int) -> int:
    return bin(n).count('1')

def state_distance(S1: list[int], S2: list[int]) -> int:
    return sum(hamming_weight(s1 ^ s2) for s1, s2 in zip(S1, S2))

def flip_single_bit(data: bytes, bit_index: int = 0) -> bytes:
    data_int = int.from_bytes(data, 'big')
    flipped_int = data_int ^ (1 << bit_index)
    return flipped_int.to_bytes(len(data), 'big')

# Replicate a single round of your Polymorphic Wire-Swap for step-by-step tracking
def acalc_single_round(S: list[int], r: int, mode: int):
    rotations = ROTATION_CRIT if mode == 1 else ROTATION_STD
    S[2] ^= (0xf0 - r*0x10 + r*0x1)
    if mode == 1: S[0], S[1] = S[1], S[0]; S[2], S[3] = S[3], S[2]
    
    S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
    T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i+1)%5] for i in range(5)]
    for i in range(5): S[i] ^= T[(i+1)%5]
    S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= 0XFFFFFFFFFFFFFFFF

    if mode == 1: S[0], S[1] = S[1], S[0]; S[2], S[3] = S[3], S[2]

    S[0] ^= rotr(S[0], rotations[0][0]) ^ rotr(S[0], rotations[0][1])
    S[1] ^= rotr(S[1], rotations[1][0]) ^ rotr(S[1], rotations[1][1])
    S[2] ^= rotr(S[2], rotations[2][0]) ^ rotr(S[2], rotations[2][1])
    S[3] ^= rotr(S[3], rotations[3][0]) ^ rotr(S[3], rotations[3][1])
    S[4] ^= rotr(S[4], rotations[4][0]) ^ rotr(S[4], rotations[4][1])

# Simulating your Zero-Overflow logic strictly up to the first permutation
def dsae_init_sac(key: bytes, nonce: bytes, params: dict):
    k_bytes = params['K_len'] // 8
    iv_val = (k_bytes << 56) | (64 << 48) | (params['R_a'] << 40) | \
             (params['R_b'] << 32) | (params['Mode'] << 24)
    
    key_padded = key + b'\x00' * (32 - len(key))
    K1 = bytes_to_int(key_padded[0:8])
    K2 = bytes_to_int(key_padded[8:16])
    K3 = bytes_to_int(key_padded[16:24])
    K4 = bytes_to_int(key_padded[24:32])
    
    S = [iv_val, K1, K2, bytes_to_int(nonce[0:8]), bytes_to_int(nonce[8:16])]
    
    # YOUR ZERO-OVERFLOW DELAYED CAPACITY XOR
    if len(key) > 16:
        S[3] ^= K3
        S[4] ^= K4
        
    return S

def run_stage4_dsae():
    print("==================================================")
    print("STAGE 4: PROPOSED DSAE ALGORITHM")
    print("==================================================")
    
    # We test your specific slices mapping to keys and dynamic modes
    scenarios = [
        {"name": "mIoT (SST=3)", "k_bytes": 16, "params": {'K_len': 128, 'R_a': 12, 'R_b': 6, 'Mode': 0}},
        {"name": "eMBB (SST=1)", "k_bytes": 24, "params": {'K_len': 192, 'R_a': 12, 'R_b': 8, 'Mode': 1}},
        {"name": "URLLC (SST=2)", "k_bytes": 32, "params": {'K_len': 256, 'R_a': 13, 'R_b': 8, 'Mode': 1}}
    ]
    
    for sc in scenarios:
        print(f"\n>>> TESTING SCENARIO: {sc['name']} | Key: {sc['k_bytes']*8}-bit <<<")
        
        base_key = get_random_bytes(sc['k_bytes'])
        nonce = get_random_bytes(16)
        flipped_key = flip_single_bit(base_key, 0)
        
        S_base = dsae_init_sac(base_key, nonce, sc['params'])
        S_flip = dsae_init_sac(flipped_key, nonce, sc['params'])
        
        print("--- Avalanche Effect (Diffusion) Test ---")
        print(f"Initial State Distance (Pre-Permutation): {state_distance(S_base, S_flip)} bits")
        
        target_diffusion = 160
        rounds_to_target = None
        
        ra = sc['params']['R_a']
        mode = sc['params']['Mode']
        
        # Step through the initialization rounds step-by-step
        for r in range(12 - ra, 12):
            acalc_single_round(S_base, r, mode)
            acalc_single_round(S_flip, r, mode)
            dist = state_distance(S_base, S_flip)
            print(f"Round {r - (12 - ra) + 1} Distance: {dist} bits")
            
            if dist >= target_diffusion and rounds_to_target is None:
                rounds_to_target = r - (12 - ra) + 1
                
        if rounds_to_target:
            print(f"-> 50% Diffusion (>= 160 bits) achieved at Round {rounds_to_target}")
        else:
            print(f"-> 50% Diffusion NOT achieved in {ra} rounds! (Max distance: {dist})")

        print("\n--- Latency Benchmark (64-byte payload) ---")
        payload = get_random_bytes(64)
        ad = get_random_bytes(16)
        latencies = []
        
        for _ in range(1000):
            iter_nonce = get_random_bytes(16) 
            start_time = time.perf_counter()
            # Calling your actual encryption function
            _ = acalc_encrypt(payload, ad, base_key, iter_nonce, sc['params'])
            end_time = time.perf_counter()
            latencies.append((end_time - start_time) * 1_000_000)
            
        print(f"Median Execution Time: {statistics.median(latencies):.2f} µs")
        print("-" * 50)

if __name__ == "__main__":
    run_stage4_dsae()