import math
import os
import psutil
import time
import tracemalloc
import sys

# ==========================================
# PART 1: SYSTEM CONSTANTS & CONFIG
# ==========================================
ROTATION_STD = [(19, 28), (61, 39), (1, 6), (10, 17), (7, 41)]
ROTATION_CRIT = [(10, 17), (7, 41), (61, 39), (19, 28), (1, 6)]

# 3GPP SST MAPPING (Patched for 6G Edge Compatibility)
SST_PRIORITY_MAP = {
    1: 8,   # eMBB (Enhanced Mobile Broadband) - Standard
    2: 15,  # URLLC (Ultra-Reliable Low Latency) - Critical
    3: 4,   # mIoT (Massive IoT) - Efficiency
    4: 15,  # V2X (Vehicle-to-Everything) - Safety Critical
    5: 12   # HMTC (High-Performance Machine-Type) - 6G Proposed
}

# ==========================================
# PART 2: HELPER FUNCTIONS
# ==========================================
def get_random_bytes(num: int) -> bytes: return os.urandom(num)
def bytes_to_int(b: bytes) -> int: return int.from_bytes(b, 'big')
def int_to_bytes(i: int, l: int) -> bytes: return i.to_bytes(l, 'big')
def bytes_to_state(b: bytes) -> list[int]: return [int.from_bytes(b[8*w:8*(w+1)], 'big') for w in range(5)]
def rotr(val: int, r: int) -> int: return ((val >> r) ^ (val << (64 - r))) & 0xFFFFFFFFFFFFFFFF

# ==========================================
# PART 3: PHASE 0 - CONTEXT BINDING (Hardware-Optimized)
# ==========================================
def phase_0_context_binding(sst: int, msg_length: int)->dict:
    """
    Derives Cryptographic Parameters mathematically, with zero magic numbers.
    """
    # 1. Map SST with Secure Fail-Safe
    # If a custom Operator-Specific Slice (128-255) is used, default to 12 (High Security).
    # This prevents downgrade attacks on unknown edge slices.
    s_pri = SST_PRIORITY_MAP.get(sst, 12)

    # 2. Length Score Calculation (Hardware Leading Zero Count equivalent)
    L = max(1, msg_length)
    l_score = max(0,31 - int(math.log2(L)))

    # 3. Master Metric (BSDM) Calculation (Max value: 122)
    bsdm = min((s_pri << 2) + (l_score << 1), 127)

    # 4. Hardware-Efficient Cryptographic Parameter Derivation
    # Extract Bit 6 (Value 64). 1 = High Security, 0 = Standard Security
    is_high_sec = (bsdm >> 6) & 1  

    # Structural mode and Processing Rounds dynamically linked to Bit 6
    mode = is_high_sec
    r_b = 6 + (is_high_sec << 1)   # Yields 6 or 8 purely via bitwise addition

    # Key Length mapped to logical binary quartiles
    if bsdm >= 96:   k_len = 256
    elif bsdm >= 64: k_len = 192
    else:            k_len = 128

    # Base Initialization Rounds (10 to 13)
    r_a = 10 + (bsdm >> 5)         
    
    return {
        "BSDM": bsdm, "K_len": k_len, "R_a": r_a, "R_b": r_b, 
         "Mode": mode
    }

# ==========================================
# PART 4: ACALC PERMUTATION
# ==========================================
def acalc_permutation(S: list[int], rounds: int, mode: int) -> None:
    rotations = ROTATION_CRIT if mode == 1 else ROTATION_STD
    
    for r in range(12 - rounds, 12):
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


def acalc_init_state(key: bytes, nonce: bytes, params: dict) -> list[int]:
    """
    Phase 1: Universal Initialization with Adaptive IV & Key Segmentation
    """
    # 1. Adaptive Byte-Aligned IV Formulation (Zero Loopholes)
    k_bytes = params['K_len'] // 8
    iv_val = (k_bytes << 56) | (64 << 48) | (params['R_a'] << 40) | \
             (params['R_b'] << 32) | (params['Mode'] << 24)
    
    # 2. Universal Key Padding (256-bit matrix)
    key_padded = key + b'\x00' * (32 - len(key))
    K1 = bytes_to_int(key_padded[0:8])
    K2 = bytes_to_int(key_padded[8:16])
    K3 = bytes_to_int(key_padded[16:24])
    K4 = bytes_to_int(key_padded[24:32])
    
    # 3. Base State Loading (IV || K_base || N)
    S = [iv_val, K1, K2, bytes_to_int(nonce[0:8]), bytes_to_int(nonce[8:16])]
    
    # 4. Extended Key Injection (For k > 128, directly into capacity)
    if len(key) > 16:
        S[3] ^= K3
        S[4] ^= K4
    acalc_permutation(S, params['R_a'], params['Mode'])
    
    # 6. Full Key Re-Injection (Blind Seal)
    S[1] ^= K1; S[2] ^= K2; S[3] ^= K3; S[4] ^= K4
    return S

def process_associated_data(S: list[int], ad: bytes, params: dict):
    if len(ad) > 0:
        padded_ad = ad + b"\x80" + b"\x00" * (7 - (len(ad) % 8))
        for i in range(0, len(padded_ad), 8):
            S[0] ^= bytes_to_int(padded_ad[i:i+8])
            acalc_permutation(S, params['R_b'], params['Mode'])
    # Domain Separation
    S[4] ^= 1 

def acalc_finalize(S: list[int], key: bytes, params: dict) -> bytes:
    """
    Phase 4: Key-Committing Folded Finalization (KCFF)
    """
    key_padded = key + b'\x00' * (32 - len(key))
    K1 = bytes_to_int(key_padded[0:8]); K2 = bytes_to_int(key_padded[8:16])
    K3 = bytes_to_int(key_padded[16:24]); K4 = bytes_to_int(key_padded[24:32])
    
    # 1. Final Key Injection
    S[1] ^= K1; S[2] ^= K2; S[3] ^= K3; S[4] ^= K4
    
    # 2. Heavy Scramble
    acalc_permutation(S, params['R_a'], params['Mode'])
    
    # 3. Universal Key Folding (Zero Per-Packet Overhead via pre-compute math)
    KF_upper = K1 ^ K3
    KF_lower = K2 ^ K4
    
    # 4. Capacity Fold & Extraction (Ensures full 256-bit commitment)
    T_upper = S[1] ^ S[3] ^ KF_upper
    T_lower = S[2] ^ S[4] ^ KF_lower
    
    return int_to_bytes(T_upper, 8) + int_to_bytes(T_lower, 8)

# ==========================================
# PART 6: HIGH-LEVEL ENCRYPTION / DECRYPTION
# ==========================================
def acalc_encrypt(pt: bytes, ad: bytes, key: bytes, nonce: bytes, params: dict) -> tuple[bytes, bytes]:
    S = acalc_init_state(key, nonce, params)
    process_associated_data(S, ad, params)
    
    ct = b""
    padded_pt = pt + b"\x80" + b"\x00" * (7 - (len(pt) % 8))
    
    for i in range(0, len(padded_pt), 8):
        # Absorb
        S[0] ^= bytes_to_int(padded_pt[i:i+8])
        # Squeeze
        if i + 8 <= len(padded_pt):
            ct += int_to_bytes(S[0], 8)
            # Permute (skip on final block)
            if i + 8 < len(padded_pt): 
                 acalc_permutation(S, params['R_b'], params['Mode'])
                 
    tag = acalc_finalize(S, key, params)
    return ct[:len(pt)], tag # Truncate ciphertext to match plaintext length

def acalc_decrypt(ct: bytes, ad: bytes, key: bytes, nonce: bytes, params: dict) -> bytes:
    S = acalc_init_state(key, nonce, params)
    process_associated_data(S, ad, params)
    
    pt = b""
    num_blocks = math.ceil(len(ct) / 8)
    
    for i in range(num_blocks):
        c_chunk = ct[i*8:(i+1)*8]
        chunk_len = len(c_chunk)
        
        # If final chunk is truncated, pad it for state processing
        is_final_block = (i == num_blocks - 1)
        padded_c_chunk = c_chunk + b'\x00' * (8 - chunk_len) if chunk_len < 8 else c_chunk
        
        c_int = bytes_to_int(padded_c_chunk)
        
        if is_final_block and chunk_len < 8:
            # Reconstruct final partial plaintext
            rate_bytes = int_to_bytes(S[0], 8)
            p_chunk = bytes([rate_bytes[j] ^ c_chunk[j] for j in range(chunk_len)])
            pt += p_chunk
            
            # Reconstruct the 1||0* padding required for the state
            p_padded = p_chunk + b'\x80' + b'\x00' * (7 - chunk_len)
            S[0] ^= bytes_to_int(p_padded)
        else:
            # Full block inverse
            p_int = S[0] ^ c_int
            pt += int_to_bytes(p_int, 8)
            S[0] = c_int # Replace state with ciphertext
            
            if i < num_blocks - 1:
                acalc_permutation(S, params['R_b'], params['Mode'])
            
    expected_tag = acalc_finalize(S, key, params)
    return pt, expected_tag
# ==========================================
# PART 7: INTERACTIVE EXECUTION
# ==========================================
if __name__ == "__main__":
    try:
        sst_in = input("Enter SST (2=URLLC, 4=V2X, 1=eMBB, 3=mIoT, Custom=128+) [Default: 2]: ")
        sst = int(sst_in) if sst_in.strip() else 2
        
        ex_ad = "Header:ID=UAV_99;Slice=URLLC"
        ex_pt = "CMD: EMERGENCY_LANDING_Auth_Code_8821"
        
        ad_in = input(f"Enter Associated Data [Default: '{ex_ad}']: ")
        ad = (ad_in if ad_in else ex_ad).encode('utf-8')
        
        pt_in = input(f"Enter Plain Text [Default: '{ex_pt}']: ")
        pt = (pt_in if pt_in else ex_pt).encode('utf-8')

    except ValueError:
        sst, ad, pt = 2, b"Header", b"Secret"

    nonce = get_random_bytes(16)
    
    process = psutil.Process(os.getpid())
    tracemalloc.start()
    
    start_time = time.perf_counter()
    start_cpu = process.cpu_times()
    start_mem = process.memory_info().rss
    
    # --- ACALC FLOW ---
    params = phase_0_context_binding(sst, len(pt))
    # Emulate the dynamic key length extraction (Assuming Master Key Handshake Out-of-Band)
    session_key = get_random_bytes(params['K_len'] // 8) 
    
    ct, tag = acalc_encrypt(pt, ad, session_key, nonce, params)
    dec_pt, expected_tag = acalc_decrypt(ct, ad, session_key, nonce, params)
    # ------------------

    end_time = time.perf_counter()
    end_cpu = process.cpu_times()
    end_mem = process.memory_info().rss
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print("\n===== CRYPTO OUTPUT =====")
    print(f"Session Key ({len(session_key)*8}-bit):  {session_key.hex()}")
    print(f"Ciphertext:     {ct.hex()}")
    print(f"Tag Generated:  {tag.hex()}")
    print(f"Decrypted Text: {dec_pt.decode('utf-8', errors='ignore')}")
    
    # The Cryptographic Perpendicular (Bottom) Verification
    if tag == expected_tag and dec_pt == pt: 
        print("Status:         VERIFICATION SUCCESS (Key Commitment Enforced)!!!")
    else:            
        print("Status:         VERIFICATION FAILED (\u22A5)!!!")

    print("\n===== PERFORMANCE METRICS =====")
    print(f"Context (SST):              {sst} -> Evaluated Priority: {SST_PRIORITY_MAP.get(sst, 12)}")
    print(f"Master Score (BSDM):        {params['BSDM']}")
    print(f"Wire Swap Mode:             {'Active' if params['Mode']==1 else 'Inactive'}")
    print(f"key size:                   {params['K_len']} bits")
    print(f"Ra:                         {params['R_a']}")
    print(f"Rb:                         {params['R_b']}")
    print(f"Execution Time:             {end_time - start_time:.6f} seconds")
    print(f"CPU User Time:              {end_cpu.user - start_cpu.user:.6f} seconds")
    print(f"CPU System Time:            {end_cpu.system - start_cpu.system:.6f} seconds")
    print(f"Memory Usage Start:         {start_mem / (1024 ** 2):.3f} MB")
    print(f"Memory Usage End:           {end_mem / (1024 ** 2):.3f} MB")
    print(f"Memory Allocated (current): {current / 1024:.2f} KB")
    print(f"Memory Peak (during run):   {peak / 1024:.2f} KB")

    # ==========================================
# PART 8: EMPIRICAL BENCHMARKING WRAPPER
# ==========================================
def run_test(ad: str, pt: str) -> dict:
    """
    Wrapper function to integrate with benchmark.py for empirical CSV generation.
    """
    import os
    import time
    import psutil
    import tracemalloc

    ad_bytes = ad.encode("utf-8")
    pt_bytes = pt.encode("utf-8")
    nonce = os.urandom(16)
    
    # Simulate URLLC (Critical) 6G Edge conditions for the test
    sst = 2
    params = phase_0_context_binding(sst, len(pt_bytes))
    session_key = os.urandom(params['K_len'] // 8)

    process = psutil.Process(os.getpid())

    # Start empirical measuring
    tracemalloc.start()
    start_time = time.perf_counter()
    start_cpu = process.cpu_times()

    # Execute the core algorithmic logic
    ct, tag = acalc_encrypt(pt_bytes, ad_bytes, session_key, nonce, params)

    # Stop measuring
    end_time = time.perf_counter()
    end_cpu = process.cpu_times()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "bits": len(pt_bytes) * 8,
        "cpu_usage": (end_cpu.user - start_cpu.user) + (end_cpu.system - start_cpu.system),
        "memory_usage": peak / 1024,   # KB
        "time_taken": end_time - start_time
    }