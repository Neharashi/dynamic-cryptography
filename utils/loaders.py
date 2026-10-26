import json
import os
import streamlit as st

def _load_json_resource(filename):
    # Ensure we look in the data directory relative to execution
    file_path = os.path.join("data", filename)
    if not os.path.exists(file_path):
        # Fallback for simpler testing if folder missing
        st.error(f"⚠️ Critical Error: '{filename}' missing in /data folder.")
        return []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        st.error(f"⚠️ Data Error: '{filename}' is corrupted.")
        return []

def load_messages(): return _load_json_resource("messages.json")
def load_associated_data(): 
    data = _load_json_resource("associated_data.json")
    return data.get("associated_data_options", [])
def load_nonces(): 
    data = _load_json_resource("nonce.json")
    return data.get("nonce_options", [])