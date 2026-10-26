import streamlit as st
import time

class FlowLogger:
    def __init__(self):
        if 'logs' not in st.session_state:
            st.session_state.logs = []
            
    def log(self, phase, title, description):
        entry = {
            "phase": phase, 
            "title": title,
            "desc": description,
            "time": time.strftime("%H:%M:%S")
        }
        st.session_state.logs.append(entry)

    def get_logs(self):
        return st.session_state.logs
        
    def clear(self):
        st.session_state.logs = []