import os
import time
import tracemalloc
import matplotlib.pyplot as plt
import numpy as np

# Import your algorithm files
import ascon128
import ascon128a
import sponge

# --- 1. Configuration ---
CPU_FREQ_HZ = 2.42e9  # Your base clock speed: 2.42 GHz
msg_lengths = [64, 256, 1024, 4096]
ITERATIONS = 1000     # Run 1000 times to average out OS background noise
SST_VALUE = 2         # URLLC target for the proposed algorithm

# Pre-generate static inputs to isolate algorithm performance
ad = os.urandom(32)
nonce = os.urandom(16)
ascon_key = os.urandom(16)

# Data structures to hold derived metrics
results = {
    'time': {'ascon128': [], 'ascon128a': [], 'proposed': []},
    'cpb':  {'ascon128': [], 'ascon128a': [], 'proposed': []},
    'mem':  {'ascon128': [], 'ascon128a': [], 'proposed': []},
    'tp':   {'ascon128': [], 'ascon128a': [], 'proposed': []}
}

# --- 2. Execution Wrappers ---
def run_ascon128(msg):
    ascon128.ascon_encrypt(ascon_key, nonce, ad, msg, "Ascon-AEAD128")

def run_ascon128a(msg):
    ascon128a.ascon_encrypt(ascon_key, nonce, ad, msg, "Ascon-128a")

def run_proposed(msg):
    # Dynamically resolve params and key size based on Sponge logic
    params = sponge.phase_0_context_binding(SST_VALUE, len(msg))
    session_key = os.urandom(params['K_len'] // 8)
    sponge.acalc_encrypt(msg, ad, session_key, nonce, params)

# --- 3. Benchmarking Core ---
def benchmark(func, msg_len, algo_name):
    msg = os.urandom(msg_len)
    
    # Measure Memory (Peak RAM allocation during execution)
    tracemalloc.start()
    func(msg) # Warmup run to initialize memory
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Measure Execution Time (High-resolution nanosecond counter)
    start_time = time.perf_counter_ns()
    for _ in range(ITERATIONS):
        func(msg)
    end_time = time.perf_counter_ns()

    # Derive Time (μs)
    avg_time_sec = ((end_time - start_time) / ITERATIONS) / 1e9
    avg_time_us = avg_time_sec * 1e6
    
    # Derive Throughput (Mbps) = (Bytes * 8) / Seconds / 1,000,000
    throughput = (msg_len * 8) / avg_time_sec / 1e6
    
    # Derive CPU Cycles Per Byte (CPB) = (Seconds * Hz) / Bytes
    cpb = (avg_time_sec * CPU_FREQ_HZ) / msg_len

    results['time'][algo_name].append(avg_time_us)
    results['cpb'][algo_name].append(cpb)
    results['mem'][algo_name].append(peak_mem)
    results['tp'][algo_name].append(throughput)

print("Running empirical benchmarks based on code logic...")
for length in msg_lengths:
    print(f"Testing message length: {length} Bytes")
    benchmark(run_ascon128, length, 'ascon128')
    benchmark(run_ascon128a, length, 'ascon128a')
    benchmark(run_proposed, length, 'proposed')

# --- 4. Plotting Separate Interfaces and Saving Images ---
labels = [f'{l}B' for l in msg_lengths]
x = np.arange(len(labels))
width = 0.25

# Vibrant, distinct color palette
color_ascon128 = '#1f77b4'   # Vibrant Blue
color_ascon128a = '#ff7f0e'  # Vibrant Orange
color_proposed = '#2ca02c'   # Vibrant Emerald Green

def plot_separate_metric(metric_key, title, ylabel, filename):
    fig, ax = plt.subplots(figsize=(9, 6))
    
    # Plot bars
    rects1 = ax.bar(x - width, results[metric_key]['ascon128'], width, label='ASCON-128', color=color_ascon128)
    rects2 = ax.bar(x, results[metric_key]['ascon128a'], width, label='ASCON-128a', color=color_ascon128a)
    rects3 = ax.bar(x + width, results[metric_key]['proposed'], width, label='Proposed (ACALC)', color=color_proposed)
    
    # Formatting the aesthetics
    ax.set_title(title, fontsize=14, fontweight='bold', pad=15)
    ax.set_ylabel(ylabel, fontsize=11, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=11)
    
    # Clean up borders (Tufte style)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#DDDDDD')
    ax.spines['bottom'].set_color('#DDDDDD')
    ax.tick_params(bottom=False, left=False)
    
    # Subtle horizontal gridlines
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, color='#EEEEEE', linestyle='-')
    
    # Add exact value labels on top of the bars
    def add_labels(rects):
        for rect in rects:
            height = rect.get_height()
            # Format to 1 decimal place if small, integer if large
            label_str = f'{height:.1f}' if height < 100 else f'{int(height)}'
            ax.annotate(label_str,
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=9, color='#333333')

    add_labels(rects1)
    add_labels(rects2)
    add_labels(rects3)
    
    # Legend
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.1), ncol=3, frameon=False, fontsize=11)
    
    plt.tight_layout()
    
    # Save the figure to the local directory
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    print(f"Saved graph as: {filename}")
    
    plt.show()

# Generate and save the four separate graphs
plot_separate_metric('time', 'Execution Time / Latency', 'Time (μs)', 'graph_execution_time.png')
plot_separate_metric('cpb', 'CPU Allocation Efficiency', 'Cycles per Byte (cpb)', 'graph_cpu_efficiency.png')
plot_separate_metric('mem', 'Memory Peak Utilization', 'Memory (Bytes)', 'graph_memory_peak.png')
plot_separate_metric('tp', 'Throughput Scaling', 'Throughput (Mbps)', 'graph_throughput.png')

print("All graphs have been saved to your folder successfully.")