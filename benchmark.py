import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Import the actual algorithm modules
import ascon128
import ascon128a
import sponge

# ==========================================
# 1. EMPIRICAL LOGIC EXECUTION
# ==========================================
TEST_STRINGS = [
    ["ad", "A"],
    ["ad", "hello"],
    ["ad", "Hello World"],
    ["ad", "0123456789"],
    ["ad", "Test1234Encryption"],
    ["ad", "!@#$%^&*()_+-={}[]|:;\"'<>,.?/"],
    ["ad", "Cryptography is fun, but subtle errors can be dangerous."],
    ["ad", "Line one.\n     Line two.    Tabbed here."],
    ["ad", "This text is intended to test how well an encryption algorithm handles longer inputs, repeated patterns, and natural language structures."],
    ["ad", "Encryption test: café, naïve, résumé, 漢字, 🚀"]
]

print("Executing cryptographic logic and compiling empirical data...")
results = []

for ad, pt in TEST_STRINGS:
    # Execute Standard ASCON-128
    r1 = ascon128.run_test(ad, pt)
    r1["implementation"] = "ascon128"

    # Execute Standard ASCON-128a
    r2 = ascon128a.run_test(ad, pt)
    r2["implementation"] = "ascon128a"

    # Execute Proposed Dynacrypt (A²F-Auth)
    r3 = sponge.run_test(ad, pt)
    r3["implementation"] = "sponge"

    results.extend([r1, r2, r3])

# Save to CSV just like the original compare.py
df = pd.DataFrame(results)
df = df[["implementation", "test_string", "bits", "cpu_usage", "memory_usage", "time_taken"]]
df.to_csv("comparison.csv", index=False)
print("Data successfully saved to 'comparison.csv'.")

# ==========================================
# 2. DATA AGGREGATION & PREPARATION
# ==========================================
# Convert bits to bytes for standard x-axis scaling
df['bytes'] = df['bits'] / 8

# Group by implementation and bytes to smooth out any interpreter spikes
# Taking the mean of the metrics for payloads of the same size
df_grouped = df.groupby(['implementation', 'bytes']).mean(numeric_only=True).reset_index()

# ==========================================
# 3. PUBLICATION-READY PLOTTING
# ==========================================
print("Generating performance graphs...")

# Set seaborn style for clean, academic grids
sns.set_theme(style="whitegrid")
fig, axes = plt.subplots(1, 3, figsize=(18, 6))

# Consistent color mapping for the algorithms
palette = {
    'ascon128': '#1f77b4',   # Blue
    'ascon128a': '#ff7f0e',  # Orange
    'sponge': '#2ca02c'   # Green
}

# --- Plot 1: Execution Time (Software Latency) ---
sns.lineplot(
    data=df_grouped, x='bytes', y='time_taken', hue='implementation', 
    marker='o', linewidth=2.5, markersize=8, palette=palette, ax=axes[0]
)
axes[0].set_title('Empirical Software Latency', fontweight='bold', pad=15)
axes[0].set_ylabel('Execution Time (Seconds)', fontweight='bold')
axes[0].set_xlabel('Message Payload (Bytes)', fontweight='bold')

# --- Plot 2: CPU Utilization ---
sns.lineplot(
    data=df_grouped, x='bytes', y='cpu_usage', hue='implementation', 
    marker='s', linewidth=2.5, markersize=8, palette=palette, ax=axes[1]
)
axes[1].set_title('Empirical CPU Overhead', fontweight='bold', pad=15)
axes[1].set_ylabel('CPU Usage Time (Seconds)', fontweight='bold')
axes[1].set_xlabel('Message Payload (Bytes)', fontweight='bold')

# --- Plot 3: Dynamic Memory Footprint ---
sns.lineplot(
    data=df_grouped, x='bytes', y='memory_usage', hue='implementation', 
    marker='^', linewidth=2.5, markersize=8, palette=palette, ax=axes[2]
)
axes[2].set_title('Python Interpreter RAM Footprint', fontweight='bold', pad=15)
axes[2].set_ylabel('Peak Memory Allocation (KB)', fontweight='bold')
axes[2].set_xlabel('Message Payload (Bytes)', fontweight='bold')



# Final formatting
for ax in axes:
    ax.legend(title='Algorithm', loc='upper left')
    # Make the x-axis strictly display the byte sizes tested
    ax.set_xticks(sorted(df_grouped['bytes'].unique()))
    ax.tick_params(axis='x', rotation=45)

plt.tight_layout()
plt.savefig('empirical_software_comparison.png', dpi=300)
print("Plot successfully saved to 'empirical_software_comparison.png'.")