import importlib.util
import time
import tracemalloc
import sys
import os
import matplotlib.pyplot as plt
import numpy as np
from unittest.mock import MagicMock

# Graceful bypass for edge environments without 'psutil'
sys.modules['psutil'] = MagicMock()

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

ascon128 = load_module("ascon128", "ascon128.py")
ascon128a = load_module("ascon128a", "ascon128a.py")
sponge = load_module("sponge", "sponge.py")

# Test Granularity exactly as requested
lengths = [32, 64, 128, 256, 512, 1024, 2048]
results = {"Ascon-128": {}, "Ascon-128a": {}, "Proposed-Sponge": {}}
iters = 10 # Iterations to smooth out OS spikes

for length in lengths:
    ad = b"header_data_for_test"
    pt = b"A" * length

    # --- Benchmark Ascon-128 ---
    tracemalloc.start()
    start_time = time.perf_counter()
    start_cpu = time.process_time()
    for _ in range(iters):
        ascon128.demo_aead(ad, pt, "Ascon-AEAD128")
    end_cpu = time.process_time()
    end_time = time.perf_counter()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    t_sec = (end_time - start_time) / iters
    cpu_sec = (end_cpu - start_cpu) / iters
    results["Ascon-128"][length] = {
        "time": t_sec * 1000,
        "cpu": cpu_sec * 1000,
        "memory": peak / 1024,
        "throughput": (length * 8) / (t_sec if t_sec > 0 else 1e-9) / 1e6
    }

    # --- Benchmark Ascon-128a ---
    tracemalloc.start()
    start_time = time.perf_counter()
    start_cpu = time.process_time()
    for _ in range(iters):
        ascon128a.demo_aead(ad, pt, "Ascon-AEAD128")
    end_cpu = time.process_time()
    end_time = time.perf_counter()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    t_sec = (end_time - start_time) / iters
    cpu_sec = (end_cpu - start_cpu) / iters
    results["Ascon-128a"][length] = {
        "time": t_sec * 1000,
        "cpu": cpu_sec * 1000,
        "memory": peak / 1024,
        "throughput": (length * 8) / (t_sec if t_sec > 0 else 1e-9) / 1e6
    }

    # --- Benchmark Proposed Sponge ---
    tracemalloc.start()
    start_time = time.perf_counter()
    start_cpu = time.process_time()
    for _ in range(iters):
        sst = 2 # Setting Slice Type (URLLC equivalent)
        params = sponge.phase_0_context_binding(sst, len(pt))
        master_key = sponge.get_random_bytes(16)
        nonce = sponge.get_random_bytes(16)
        s_key = sponge.acalc_gen_session_key(master_key, params, nonce)
        ct, tag = sponge.acalc_encrypt(pt, ad, s_key, nonce, params)
        dec_pt = sponge.acalc_decrypt(ct, ad, s_key, nonce, params)
    end_cpu = time.process_time()
    end_time = time.perf_counter()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    t_sec = (end_time - start_time) / iters
    cpu_sec = (end_cpu - start_cpu) / iters
    results["Proposed-Sponge"][length] = {
        "time": t_sec * 1000,
        "cpu": cpu_sec * 1000,
        "memory": peak / 1024,
        "throughput": (length * 8) / (t_sec if t_sec > 0 else 1e-9) / 1e6
    }

# === GRAPHING ENGINE ===
labels = [f"{l} B" for l in lengths]
x = np.arange(len(labels))
width = 0.25

metrics = [
    ('time', 'Execution Time / Latency (ms)', 'Latency Comparison (Lower is Better)'),
    ('cpu', 'CPU Processing Time (ms)', 'CPU Overhead Comparison (Lower is Better)'),
    ('throughput', 'Throughput (Mbps)', 'Throughput Comparison (Higher is Better)'),
    ('memory', 'Peak Memory Usage (KB)', 'Memory Footprint Comparison (Lower is Better)')
]

for key, ylabel, title in metrics:
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x - width, [results["Ascon-128"][l][key] for l in lengths], width, label='Ascon-128', color='#1f77b4')
    ax.bar(x, [results["Ascon-128a"][l][key] for l in lengths], width, label='Ascon-128a', color='#ff7f0e')
    ax.bar(x + width, [results["Proposed-Sponge"][l][key] for l in lengths], width, label='Proposed-Sponge', color='#2ca02c')
    ax.set_ylabel(ylabel)
    ax.set_xlabel('Message Length (Bytes)')
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.show() # Can swap to plt.savefig("filename.png") for automation