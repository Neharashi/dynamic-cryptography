import streamlit as st
import time
import secrets
from core.crypto_engine import CryptoEngine
from utils.loaders import load_messages, load_associated_data, load_nonces
from utils.ui_helpers import render_pipeline_css, render_flow_step, render_clean_definition

# --- PAGE CONFIG ---
st.set_page_config(page_title="Dynamic Cryptography in 6G", page_icon="🛡️", layout="wide")

# --- STATE ---
if "msg_index" not in st.session_state: st.session_state["msg_index"] = 0
if "status" not in st.session_state: st.session_state["status"] = "INPUT"
if "crypto_data" not in st.session_state: st.session_state["crypto_data"] = {}

def reset_system():
    st.session_state["status"] = "INPUT"
    st.session_state["crypto_data"] = {}

def next_message():
    st.session_state["msg_index"] = (st.session_state["msg_index"] + 1) % len(load_messages())
    reset_system()

def start_encryption(ad_val, raw_msg, nonce_type):
    st.session_state["crypto_data"] = {
        "key": b"0123456789ABCDEF",
        "nonce": secrets.token_bytes(16),
        "ad_bytes": ad_val.encode(),
        "pt_bytes": raw_msg.encode(),
    }
    st.session_state["status"] = "ENCRYPTING"

def start_decryption():
    st.session_state["status"] = "DECRYPTING"

# --- RENDER CSS ---
render_pipeline_css()

# 1. HEADER
col_head, col_reset = st.columns([6, 1])
with col_head:
    st.title("Dynamic Cryptography in 6G")
with col_reset:
    if st.button("↺ RESET", help="Reset Simulation"):
        reset_system()
        st.rerun()

# 2. DEFINITION & ANALOGY (Vertical & Brief)
st.markdown("""
<div class="intro-container">
    <div class="intro-section">
        <div class="intro-title">⚡ The Algorithm</div>
        <div class="intro-text">
            <strong>Dynacrypt</strong> is a lightweight authenticated encryption scheme for 6G IoT. It uses a <strong>Sponge Construction</strong> to continuously fuse the message with the device's internal state ("The Gears"), ensuring every bit is both encrypted and authenticated in one pass.
        </div>
    </div>
    <div class="intro-divider-h"></div>
    <div class="intro-section">
        <div class="intro-title">🏭 The Analogy</div>
        <div class="intro-text">
            Think of a <strong>Digital Factory</strong>. The Key is the <strong>Blueprint</strong>, and the Nonce is the <strong>Timestamp</strong>. 
            The system builds a machine that evolves as it runs. To unlock the message, the Receiver must build the <em>exact same machine</em>. If even one bit is forged, the gears jam.
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# 3. DEFINITIONS
st.markdown("<br>", unsafe_allow_html=True)
col_d1, col_d2 = st.columns(2)
with col_d1:
    render_clean_definition("ASSOCIATED DATA (Label)", "Public context (e.g., Device ID). Integrates into the seal.")
with col_d2:
    render_clean_definition("NONCE (Timestamp)", "Unique value ensuring freshness. Prevents replay attacks.")

# 4. INPUTS
MESSAGES = load_messages()
AD_OPTIONS = load_associated_data()
NONCE_OPTIONS = load_nonces()

msg_obj = MESSAGES[st.session_state["msg_index"]]
raw_msg = msg_obj["message"]

st.markdown("### 1. Message Payload")
st.info(f"📄 {raw_msg}")

st.markdown("### 2. Security Parameters")
c1, c2 = st.columns(2)
with c1:
    ad_choice = st.selectbox("Select Associated data:", AD_OPTIONS, format_func=lambda x: x['label'], 
                             disabled=(st.session_state["status"] != "INPUT"), key="ad_sel")
with c2:
    nonce_choice = st.selectbox("Select Nonce:", NONCE_OPTIONS, format_func=lambda x: x['label'], 
                                disabled=(st.session_state["status"] != "INPUT"), key="nonce_sel")

# 5. START BUTTON
if st.session_state["status"] == "INPUT":
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🚀 START FACTORY (ENCRYPT)", type="primary", use_container_width=True):
        start_encryption(ad_choice['value'], raw_msg, nonce_choice['type'])
        st.rerun()

# 6. EXECUTION AREA
if st.session_state["status"] != "INPUT":
    st.markdown("---")
    col_enc, col_mid, col_dec = st.columns([4, 0.4, 4])
    
    # ENCRYPTION
    with col_enc:
        st.markdown("### 🟦 Sender (Encryption)")
        enc_container = st.container()
        
        if st.session_state["status"] == "ENCRYPTING":
            engine = CryptoEngine(render_callback=lambda d: render_flow_step(enc_container, d, theme="blue"), step_delay=2.0, mode="encrypt")
            d = st.session_state["crypto_data"]
            ct, tag = engine.encrypt_cycle(d["ad_bytes"], d["pt_bytes"], d["key"], d["nonce"])
            d["ct"] = ct; d["tag"] = tag
            st.session_state["status"] = "WAIT_FOR_DECRYPT"
            st.rerun()
        else:
            engine = CryptoEngine(render_callback=lambda d: render_flow_step(enc_container, d, theme="blue"), step_delay=0, mode="encrypt")
            d = st.session_state["crypto_data"]
            engine.encrypt_cycle(d["ad_bytes"], d["pt_bytes"], d["key"], d["nonce"])
            st.success("✅ Encryption Complete")
            st.code(f"Tag: {d['tag'].hex()}", language="text")

    # DECRYPTION
    with col_dec:
        st.markdown("### 🟩 Receiver (Decryption)")
        dec_container = st.container()

        if st.session_state["status"] == "WAIT_FOR_DECRYPT":
            st.info("Packet pending transmission...")
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("📡 TRANSMIT & DECRYPT", type="primary", use_container_width=True):
                start_decryption()
                st.rerun()
        
        elif st.session_state["status"] == "DECRYPTING":
            engine = CryptoEngine(render_callback=lambda d: render_flow_step(dec_container, d, theme="green"), step_delay=2.0, mode="decrypt")
            d = st.session_state["crypto_data"]
            pt, calc_tag = engine.decrypt_cycle(d["ad_bytes"], d["ct"], d["tag"], d["key"], d["nonce"])
            st.session_state["status"] = "FINISHED"
            st.rerun()

        elif st.session_state["status"] == "FINISHED":
            engine = CryptoEngine(render_callback=lambda d: render_flow_step(dec_container, d, theme="green"), step_delay=0, mode="decrypt")
            d = st.session_state["crypto_data"]
            engine.decrypt_cycle(d["ad_bytes"], d["ct"], d["tag"], d["key"], d["nonce"])
            
            st.markdown(f"""
            <div style='background:rgba(6, 78, 59, 0.5); padding:15px; border-radius:8px; border:1px solid #10b981; text-align:center; margin-top:20px;'>
                <h3 style='color:#34d399; margin:0'>✔ AUTHENTICATED</h3>
                <div style='color:#ecfdf5; margin-top:5px; font-family:monospace; font-size:1.1em;'>{d['pt_bytes'].decode(errors='ignore')}</div>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("➡ NEXT MESSAGE", use_container_width=True):
                next_message()
                st.rerun()