import matplotlib.pyplot as plt
import numpy as np
import json
from matplotlib import rcParams

# Set global font and style
rcParams['font.sans-serif'] = ['Arial', 'Helvetica']
rcParams['axes.unicode_minus'] = False

# Test result data
results_data = {
    "timestamp": "20251121_024141",
    "config": {
        "baud_rate": 115200,
        "timeout": 60,
        "test_iterations": 5,
        "file_sizes": [1024, 4096, 8192, 32768, 65536],
        "ports": {
            "AES_Hardware": "COM3",
            "AES_Software": "COM3",
            "Ascon_Software": "COM3"
        }
    },
    "results": {
        "AES_Hardware": {
            "1024": {"avg_throughput_kbps": 0.21322897967547844, "stability": 0.031734215326048726},
            "4096": {"avg_throughput_kbps": 0.7218433414572115, "stability": 0.292348173820707},
            "8192": {"avg_throughput_kbps": 1.201891814889723, "stability": 0.1062473236955812},
            "32768": {"avg_throughput_kbps": 2.386693819316673, "stability": 0.07309525903507343},
            "65536": {"avg_throughput_kbps": 2.8512388564421682, "stability": 0.24138487645556556}
        },
        "AES_Software": {
            "1024": {"avg_throughput_kbps": 0.21283718689342032, "stability": 0.09496310391744417},
            "4096": {"avg_throughput_kbps": 0.717306357355852, "stability": 0.11708022310870014},
            "8192": {"avg_throughput_kbps": 1.1843835492766528, "stability": 0.15259025614942026},
            "32768": {"avg_throughput_kbps": 2.3246173669801395, "stability": 0.5103259376803566},
            "65536": {"avg_throughput_kbps": 2.762035135859698, "stability": 0.5532037311802251}
        },
        "Ascon_Software": {
            "1024": {"avg_throughput_kbps": 0.21221040428544446, "stability": 0.05854987102301098},
            "4096": {"avg_throughput_kbps": 0.7024556742542792, "stability": 0.5546572342874289},
            "8192": {"avg_throughput_kbps": 1.1593156160012565, "stability": 0.9277981613689968},
            "32768": {"avg_throughput_kbps": 2.283636861572823, "stability": 0.6796987573930239},
            "65536": {"avg_throughput_kbps": 2.7476437096320403, "stability": 0.8125205137098791}
        }
    },
    "summary": {
        "AES_Hardware": {
            "performance_rank": 1,
            "avg_throughput_kbps": 1.4749793623562508,
            "efficiency_percent": 13.110927665388896
        },
        "AES_Software": {
            "performance_rank": 2,
            "avg_throughput_kbps": 1.4402359192731524,
            "efficiency_percent": 12.8020970602058
        },
        "Ascon_Software": {
            "performance_rank": 3,
            "avg_throughput_kbps": 1.4210524531491686,
            "efficiency_percent": 12.631577361325943
        }
    }
}

# ELF file analysis data
elf_data = {
    'AES_Hardware': {'code_size': 14580, 'ram_usage': 14230, 'flash_usage': 16910},
    'AES_Software': {'code_size': 15070, 'ram_usage': 14230, 'flash_usage': 17910},
    'Ascon_Software': {'code_size': 41460, 'ram_usage': 14250, 'flash_usage': 43770}
}

# Create figure with adjusted spacing and smaller subplots
fig = plt.figure(figsize=(20, 16))

# Add more space for the main title
plt.subplots_adjust(wspace=0.35, hspace=0.5, top=0.90, bottom=0.08, left=0.07, right=0.95)

# Add main title with more space
fig.suptitle('Encryption Algorithms Performance Comprehensive Comparison\n(Robust Benchmark Results)', 
             fontsize=16, fontweight='bold', y=0.98)

# 1. Throughput Comparison - smaller subplot
ax1 = plt.subplot(2, 3, 1)
file_sizes = results_data['config']['file_sizes']
algorithms = ['AES_Hardware', 'AES_Software', 'Ascon_Software']
colors = ['#2E86AB', '#A23B72', '#F18F01']

for i, algo in enumerate(algorithms):
    throughputs = [results_data['results'][algo][str(size)]['avg_throughput_kbps'] for size in file_sizes]
    ax1.plot(file_sizes, throughputs, marker='o', linewidth=2, label=algo, color=colors[i], markersize=5)
    # Add fewer data labels to avoid overlap
    for j, (x, y) in enumerate(zip(file_sizes, throughputs)):
        if j == 0 or j == len(file_sizes)-1:  # Only label first and last points
            ax1.annotate(f'{y:.3f}', (x, y), textcoords="offset points", xytext=(0,8), 
                        ha='center', va='bottom', fontsize=8)

ax1.set_xlabel('File Size (Bytes)', fontsize=10)
ax1.set_ylabel('Throughput (kbps)', fontsize=10)
ax1.set_title('Throughput vs File Size', fontsize=12, fontweight='bold', pad=10)
ax1.legend(fontsize=9)
ax1.grid(True, alpha=0.3)
ax1.set_xscale('log')
ax1.tick_params(axis='both', which='major', labelsize=9)

# 2. Stability Comparison - smaller subplot
ax2 = plt.subplot(2, 3, 2)
for i, algo in enumerate(algorithms):
    stabilities = [results_data['results'][algo][str(size)]['stability'] for size in file_sizes]
    ax2.plot(file_sizes, stabilities, marker='s', linewidth=2, label=algo, color=colors[i], markersize=5)

ax2.set_xlabel('File Size (Bytes)', fontsize=10)
ax2.set_ylabel('Stability (Lower is Better)', fontsize=10)
ax2.set_title('Algorithm Stability', fontsize=12, fontweight='bold', pad=10)
ax2.legend(fontsize=9)
ax2.grid(True, alpha=0.3)
ax2.set_xscale('log')
ax2.tick_params(axis='both', which='major', labelsize=9)

# 3. Average Performance Comparison - smaller subplot
ax3 = plt.subplot(2, 3, 3)
avg_throughputs = [results_data['summary'][algo]['avg_throughput_kbps'] for algo in algorithms]
efficiency = [results_data['summary'][algo]['efficiency_percent'] for algo in algorithms]

x = np.arange(len(algorithms))
width = 0.35

bars1 = ax3.bar(x - width/2, avg_throughputs, width, label='Avg Throughput (kbps)', color='#2E86AB', alpha=0.8)
bars2 = ax3.bar(x + width/2, efficiency, width, label='Efficiency (%)', color='#A23B72', alpha=0.8)

ax3.set_xlabel('Algorithm Type', fontsize=10)
ax3.set_ylabel('Performance Metrics', fontsize=10)
ax3.set_title('Average Performance', fontsize=12, fontweight='bold', pad=10)
ax3.set_xticks(x)
ax3.set_xticklabels(algorithms, fontsize=9)
ax3.legend(fontsize=9)
ax3.grid(True, alpha=0.3)
ax3.tick_params(axis='both', which='major', labelsize=9)

# Add value labels with smaller font
for bar in bars1:
    height = bar.get_height()
    ax3.text(bar.get_x() + bar.get_width()/2., height + 0.03,
             f'{height:.3f}', ha='center', va='bottom', fontsize=8, fontweight='bold')

for bar in bars2:
    height = bar.get_height()
    ax3.text(bar.get_x() + bar.get_width()/2., height + 0.03,
             f'{height:.2f}%', ha='center', va='bottom', fontsize=8, fontweight='bold')

# 4. Resource Usage Comparison - smaller subplot
ax4 = plt.subplot(2, 3, 4)
resources = ['code_size', 'ram_usage', 'flash_usage']
resource_labels = ['Code Size', 'RAM Usage', 'Flash Usage']
x = np.arange(len(resources))
width = 0.25

for i, algo in enumerate(algorithms):
    values = [elf_data[algo][resource] for resource in resources]
    bars = ax4.bar(x + i*width, values, width, label=algo, color=colors[i], alpha=0.8)
    # Add value labels with smaller font
    for bar, value in zip(bars, values):
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + 50,
                 f'{value}', ha='center', va='bottom', fontsize=8, fontweight='bold')

ax4.set_xlabel('Resource Type', fontsize=10)
ax4.set_ylabel('Usage (Bytes)', fontsize=10)
ax4.set_title('Resource Usage', fontsize=12, fontweight='bold', pad=10)
ax4.set_xticks(x + width)
ax4.set_xticklabels(resource_labels, fontsize=9)
ax4.legend(fontsize=9)
ax4.grid(True, alpha=0.3)
ax4.tick_params(axis='both', which='major', labelsize=9)

# 5. Performance Ranking - smaller subplot
ax5 = plt.subplot(2, 3, 5)
ranks = [results_data['summary'][algo]['performance_rank'] for algo in algorithms]
throughputs = [results_data['summary'][algo]['avg_throughput_kbps'] for algo in algorithms]

# Sort by rank
sorted_indices = np.argsort(ranks)
sorted_algorithms = [algorithms[i] for i in sorted_indices]
sorted_throughputs = [throughputs[i] for i in sorted_indices]

bars = ax5.barh(sorted_algorithms, sorted_throughputs, 
                color=['gold', 'silver', '#CD7F32'])  # Gold, Silver, Bronze
ax5.set_xlabel('Average Throughput (kbps)', fontsize=10)
ax5.set_title('Performance Ranking', fontsize=12, fontweight='bold', pad=10)
ax5.grid(True, alpha=0.3)
ax5.tick_params(axis='both', which='major', labelsize=9)

# Add ranking labels with smaller font
for i, (bar, algo) in enumerate(zip(bars, sorted_algorithms)):
    width = bar.get_width()
    rank_text = f'Rank {ranks[sorted_indices[i]]}'
    ax5.text(width + 0.05, bar.get_y() + bar.get_height()/2, 
             f'{width:.3f} kbps\n{rank_text}', 
             va='center', ha='left', fontsize=9, fontweight='bold')

# 6. Comprehensive Radar Chart - smaller subplot
ax6 = plt.subplot(2, 3, 6, polar=True)

# Radar chart metrics
categories = ['Throughput', 'Stability', 'Code Efficiency', 'RAM Efficiency', 'Flash Efficiency']
N = len(categories)

# Normalize data (higher is better)
def normalize_data(values, higher_better=True):
    if higher_better:
        return [v/max(values) for v in values]
    else:
        return [min(values)/v if v != 0 else 0 for v in values]

throughput_norm = normalize_data([results_data['summary'][algo]['avg_throughput_kbps'] for algo in algorithms])
stability_norm = normalize_data([np.mean([results_data['results'][algo][str(size)]['stability'] for size in file_sizes]) for algo in algorithms], False)
code_eff_norm = normalize_data([1/elf_data[algo]['code_size'] for algo in algorithms])
ram_eff_norm = normalize_data([1/elf_data[algo]['ram_usage'] for algo in algorithms])
flash_eff_norm = normalize_data([1/elf_data[algo]['flash_usage'] for algo in algorithms])

values = list(zip(throughput_norm, stability_norm, code_eff_norm, ram_eff_norm, flash_eff_norm))

angles = [n / float(N) * 2 * np.pi for n in range(N)]
angles += angles[:1]

for i, algo in enumerate(algorithms):
    algo_values = values[i]
    algo_values += algo_values[:1]
    ax6.plot(angles, algo_values, 'o-', linewidth=2, label=algo, color=colors[i], markersize=4)
    ax6.fill(angles, algo_values, alpha=0.15, color=colors[i])

ax6.set_xticks(angles[:-1])
ax6.set_xticklabels(categories, fontsize=9)
ax6.set_ylim(0, 1)
ax6.set_yticks([0.2, 0.4, 0.6, 0.8])
ax6.set_yticklabels(['0.2', '0.4', '0.6', '0.8'], fontsize=8)
ax6.set_title('Performance Radar Chart', fontsize=12, fontweight='bold', pad=15)
ax6.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=9)

# Save the figure
plt.savefig('encryption_performance_comparison.png', dpi=300, bbox_inches='tight')
plt.show()

# Output statistical summary
print("=" * 70)
print("ENCRYPTION ALGORITHMS PERFORMANCE TEST SUMMARY")
print("=" * 70)
print(f"Test Time: {results_data['timestamp']}")
print(f"Test Config: {results_data['config']['baud_rate']} baud, {results_data['config']['test_iterations']} iterations")
print("\nPERFORMANCE RANKING:")
for algo in algorithms:
    summary = results_data['summary'][algo]
    print(f"  {algo}: Rank {summary['performance_rank']} - {summary['avg_throughput_kbps']:.3f} kbps")

print("\nRESOURCE USAGE:")
for algo in algorithms:
    data = elf_data[algo]
    print(f"  {algo}: Code {data['code_size']}B, RAM {data['ram_usage']}B, Flash {data['flash_usage']}B")

print("\nKEY FINDINGS:")
print("1. AES Hardware version shows best throughput performance")
print("2. AES Software version has similar performance to Hardware but higher resource usage")
print("3. Ascon algorithm consumes significantly more resources with lower performance")
print("4. All algorithms perform better with larger file sizes")
print("5. Hardware acceleration provides measurable performance benefits")
print("\n" + "=" * 70)