import math
import time
from typing import Callable, List

# --- CONSTANTS ---
RATE = 8
DS_INIT = 1 << 63
Rc_0 = 11400714819323197440
MASK64 = (1 << 64) - 1

# --- HELPER FUNCTIONS ---
def to_bytes(l: bytes | list[int]) -> bytes:
    return bytes(bytearray(l))

def zero_bytes(n: int) -> bytes:
    return n * b"\x00"

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "little")

def int_to_bytes(integer: int, nbytes: int) -> bytes:
    return integer.to_bytes(nbytes, "little")

def bytes_to_state(b: bytes, length: int) -> list[int]:
    return [bytes_to_int(b[8*w:8*(w+1)]) for w in range(length)]

def rotl(val: int, r: int) -> int:
    return ((val << r) & MASK64) | ((val & MASK64) >> (64 - r))

class CryptoEngine:
    def __init__(self, render_callback: Callable = None, step_delay: float = 2.0, mode="encrypt"):
        self.render_callback = render_callback
        self.step_delay = step_delay
        self.mode = mode 
        self.S = [0] * 5
        self.key = None
        self.nonce = None
        self.Ra = 12
        self.Rb = 6
        self.key_size = 0

    def _log(self, phase, title, explanation, math_latex=None,output_preview=None):
        if self.render_callback:
            step_data = {
                "phase": phase,
                "title": title,
                "explanation": explanation,
                "math_html": math_latex,
                "output_preview":output_preview
            }
            self.render_callback(step_data)
            time.sleep(self.step_delay)

    def _permutate(self, R: int, context_desc=""):
        S = self.S
        
        # S-Box Logic
        math_latex = r"""
        T_0 = (S_0 \lor S_1) \land (S_1 \lor S_2 \lor S_3) \dots \\
        S_0 \leftarrow S_0 \oplus \text{rotl}(T_1, 7) \oplus \text{rotl}(T_2, 41)
        """
        
        # Only log perm details during specific phases
        if context_desc == "Initial Setup":
             self._log("PERM", f"Mixing Gears ({context_desc})", 
                       "The internal state passes through the non-linear S-Box. Bits melt, rotate, and reform so no pattern survives.", 
                       math_latex)

        for p in range(R):
            S[2] ^= (p * Rc_0) & MASK64
            T = []
            T.append((S[0] | S[1]) & (S[1] | S[2] | S[3]) & (S[1] | S[4] | ~S[3]) & (S[3] | ~S[0] | ~S[1] | ~S[2]) & (~S[0] | ~S[1] | ~S[3] | ~S[4]))
            T.append((S[1] | S[2]) & (S[2] | S[3] | S[4]) & (S[0] | S[2] | ~S[4]) & (S[4] | ~S[1] | ~S[2] | ~S[3]) & (~S[0] | ~S[1] | ~S[2] | ~S[4]))
            T.append((S[2] | S[3]) & (S[0] | S[3] | S[4]) & (S[1] | S[3] | ~S[0]) & (S[0] | ~S[2] | ~S[3] | ~S[4]) & (~S[0] | ~S[1] | ~S[2] | ~S[3]))
            T.append((S[3] | S[4]) & (S[0] | S[1] | S[4]) & (S[2] | S[4] | ~S[1]) & (S[1] | ~S[0] | ~S[3] | ~S[4]) & (~S[1] | ~S[2] | ~S[3] | ~S[4]))
            T.append((S[0] | S[4]) & (S[0] | S[1] | S[2]) & (S[0] | S[3] | ~S[2]) & (S[2] | ~S[0] | ~S[1] | ~S[4]) & (~S[0] | ~S[2] | ~S[3] | ~S[4]))
            T = [x & MASK64 for x in T]
            S[0] ^= rotl(T[1],  7) ^ rotl(T[2], 41)
            S[1] ^= rotl(T[2], 10) ^ rotl(T[3], 17)
            S[2] ^= rotl(T[3],  1) ^ rotl(T[4],  6)
            S[3] ^= rotl(T[4], 61) ^ rotl(T[0], 39)
            S[4] ^= rotl(T[0], 19) ^ rotl(T[1], 28)
            self.S = [x & MASK64 for x in S]

    def initialize(self, key: bytes, nonce_bytes: bytes):
        self.key = key
        self.key_size = len(key)
        self.Ra = 12 + math.floor((self.key_size - 16) / 8)
        self.Rb = self.Ra - 6
        
        k_padded = key + to_bytes([0x80]) + zero_bytes((RATE - (len(key) % RATE) - 1))
        k = bytes_to_state(k_padded, 5)
        n = bytes_to_state(nonce_bytes, 2)
        
        self.S = k[:] 
        self.S[0] ^= n[0]
        self.S[1] ^= n[1]
        self.S[2] = k[3]
        self.S[3] = self.S[0] ^ self.S[1]
        self.S[4] = DS_INIT ^ k[2]
        
        math_latex = r"""
        S_{0..4} = \text{Blueprint}(K) \oplus \text{Stamp}(N) \\
        S_3 = S_0 \oplus S_1
        """
        
        # DISTINCT TEXT FOR RECEIVER VS SENDER
        if self.mode == "encrypt":
            self._log("SETUP", "Step 1: Forging the Lock", 
                      "The Factory creates 5 unique gears using the Master Key (Blueprint) and Nonce (Time-stamp).", 
                      math_latex)
        else:
            self._log("SETUP", "Step 1: Rebuilding the Machine", 
                      "The Receiver re-creates the exact gear configuration using their copy of the Key and the received Nonce.", 
                      math_latex)

        self._permutate(self.Ra, context_desc="Initial Setup")
        
        self.S[0] ^= 0
        self.S[1] ^= k[0]
        self.S[2] ^= k[1]
        self.S[3] ^= k[2]
        self.S[4] ^= k[3]

    def process_associated_data(self, ad: bytes):
        if len(ad) > 0:
            a_padded = ad + to_bytes([0x80]) + zero_bytes((RATE - (len(ad) % RATE) - 1))
            for i in range(0, len(a_padded), RATE):
                block = bytes_to_int(a_padded[i:i+RATE])
                self.S[0] ^= block
                self._permutate(self.Rb, context_desc="")
                
        self.S[4] ^= 2 
        
        if self.mode == "encrypt":
            self._log("AD", "Step 2: Sealing Shipping Labels", 
                      "Associated Data and Domain Separator absorbed into state.", 
                      r"S_0 \leftarrow S_0 \oplus \text{AD}; \quad S_4 \leftarrow S_4 \oplus 2")
        else:
            self._log("AD", "Step 2: Verifying Labels", 
                      "Receiver absorbs the public Associated Data to match the Sender's state.", 
                      r"S_0 \leftarrow S_0 \oplus \text{AD}")

    def process_plain_text(self, plaintext: bytes) -> bytes:
        p_lastlen = len(plaintext) % RATE
        p_padding = to_bytes([0x80]) + zero_bytes(RATE - p_lastlen - 1)
        p_padded = plaintext + p_padding
        ciphertext = b""
        block = 0
        loop = len(plaintext) // RATE
        
        for i in range(loop):
            input_block = bytes_to_int(p_padded[block : block+8])
            self.S[2] = self.S[0] ^ input_block 
            ct_chunk = int_to_bytes(self.S[2], RATE)
            ciphertext += ct_chunk
            
            # SHOW CIPHERTEXT OUTPUT
            hex_out = ct_chunk.hex().upper()
            math_latex = r"C_i = S_0 \oplus P_i"
            self._log("ENCRYPT", f"Step 3: Welding Block {i+1}", 
                      "Fusing the plaintext block into the gears to create ciphertext.", 
                      math_latex,
                      output_preview=f"Output: {hex_out}")
            
            self._permutate(self.Rb, context_desc="")
            block += RATE

        last_input_bytes = p_padded[len(plaintext)-p_lastlen:]
        last_input = bytes_to_int(last_input_bytes)
        ct_val = self.S[0] ^ last_input
        self.S[2] = ct_val 
        ct_final = int_to_bytes(ct_val, RATE)
        ciphertext += ct_final
        
        # Final block log
        self._log("ENCRYPT", "Welding Final Fragment", 
                  "Fusing the last piece of the message.", 
                  r"C_{last} = S_0 \oplus P_{last}",
                  output_preview=f"Output: {ct_final.hex().upper()}")
        return ciphertext[:len(plaintext)]

    def process_cipher_text(self, ciphertext: bytes) -> bytes:
        c_lastlen = len(ciphertext) % RATE
        plaintext = b""
        block = 0
        loop = len(ciphertext) // RATE

        for i in range(loop):
            ct_block = bytes_to_int(ciphertext[block:block+8])
            pt_block = self.S[0] ^ ct_block
            pt_chunk = int_to_bytes(pt_block, 8)
            plaintext+=pt_chunk
            self.S[2] = ct_block
            
            # Show Recovered Text
            text_out = pt_chunk.decode(errors='ignore').replace('\x00','')
            math_latex = r"P_i = S_0 \oplus C_i"
            self._log("DECRYPT", f"Step 3: Unlocking Block {i+1}", 
                      "Reversing the weld to reveal the hidden Plaintext.", 
                      math_latex,
                      output_preview=f"Recovered: '{text_out}'")
            
            self._permutate(self.Rb, context_desc="")
            block += RATE

        last_ct_chunk = ciphertext[len(ciphertext)-c_lastlen:]
        s0_bytes = int_to_bytes(self.S[0], 8)
        pt_tilda_int = bytes_to_int(s0_bytes[:c_lastlen]) ^ bytes_to_int(last_ct_chunk)
        pt_tilda = int_to_bytes(pt_tilda_int, c_lastlen)
        pt_padded = pt_tilda + to_bytes([0x80]) + zero_bytes(RATE - c_lastlen - 1)
        plaintext += pt_tilda
        self.S[2] = self.S[0] ^ bytes_to_int(pt_padded) 
        
        text_final = pt_tilda.decode(errors='ignore')
        self._log("DECRYPT", "Unlocking Final Fragment", 
                  "Recovering the last message fragment.", 
                  None,
                  output_preview=f"Recovered: '{text_final}'")
        return plaintext

    def finalize(self) -> bytes:
        k_padded = self.key + to_bytes([0x80]) + zero_bytes((RATE - (len(self.key) % RATE) - 1))
        k = bytes_to_state(k_padded, 5)
        
        self.S[0] ^= Rc_0
        self.S[1] ^= k[0]
        self.S[2] ^= k[1]
        self.S[3] ^= k[2]
        self.S[4] ^= k[3]
        
        self._permutate(self.Ra, context_desc="Finalization")
        
        skip_len = abs(self.key_size - 16)
        key_full = self.key + b"\x00"*16 
        k_part1 = bytes_to_int(key_full[skip_len : skip_len+8])
        k_part2 = bytes_to_int(key_full[skip_len+8 : skip_len+16])
        self.S[3] ^= k_part1
        self.S[4] ^= k_part2
        
        tag_int = (self.S[3] & MASK64) | ((self.S[4] & MASK64) << 64)
        
        math_latex = r"\text{Tag} = S_3 \parallel S_4"
        
        if self.mode == "encrypt":
            self._log("TAG", "Step 4: Stamping Authenticity", 
                      "Generating unique Tag from final state.", math_latex)
        else:
             self._log("TAG", "Step 4: Generating Verification Seal", 
                      "Receiver squeezes their final state to see if it matches the Sender's seal.", math_latex)
        
        return int_to_bytes(tag_int, 16)

    def encrypt_cycle(self, associated_data: bytes, plain_text: bytes, key: bytes, nonce: bytes):
        self.initialize(key, nonce)
        self.process_associated_data(associated_data)
        ct = self.process_plain_text(plain_text)
        tag = self.finalize()
        return ct, tag

    def decrypt_cycle(self, associated_data: bytes, cipher_text: bytes, tag: bytes, key: bytes, nonce: bytes):
        self.initialize(key, nonce)
        self.process_associated_data(associated_data)
        pt = self.process_cipher_text(cipher_text)
        calced_tag = self.finalize()
        return pt, calced_tag