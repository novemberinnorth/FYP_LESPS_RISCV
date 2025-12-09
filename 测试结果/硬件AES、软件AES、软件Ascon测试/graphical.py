import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.gridspec import GridSpec

# 设置英文样式
sns.set_style("whitegrid")
sns.set_palette("husl")

# 读取数据
def load_benchmark_data(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

# 加载数据
data_hardware_aes = load_benchmark_data('benchmark_硬件AES-GCM-SIV_20251208_165517.json')
data_software_aes = load_benchmark_data('benchmark_软件AES-GCM-SIV_20251208_211100.json')
data_software_ascon = load_benchmark_data('benchmark_软件Ascon_20251209_013209.json')

# 正确的资源占用信息
resource_data = {
    "Hardware AES-GCM-SIV": {
        "Flash": 21.87,  # KB
        "RAM": 14.81,    # KB
        "Code Size": 18.48  # KB
    },
    "Software AES-GCM-SIV": {
        "Flash": 21.72,
        "RAM": 14.81,
        "Code Size": 18.11
    },
    "Software Ascon": {
        "Flash": 46.90,
        "RAM": 14.84,
        "Code Size": 43.67
    }
}

# 准备数据
def extract_summary_data(data_dict, name):
    test_cases = []
    for case in data_dict['test_cases']:
        summary = case['summary']
        test_cases.append({
            'project': name,
            'file_name': case['file_name'],
            'file_size': case['file_size'],
            'avg_encryption_throughput': summary['avg_encryption_throughput'],
            'avg_decryption_throughput': summary['avg_decryption_throughput'],
            'avg_total_throughput': summary['avg_total_throughput'],
            'std_encryption_throughput': summary['std_encryption_throughput'],
            'std_decryption_throughput': summary['std_decryption_throughput'],
            'std_total_throughput': summary['std_total_throughput']
        })
    return pd.DataFrame(test_cases)

# 创建DataFrame
df_hardware = extract_summary_data(data_hardware_aes, "Hardware AES-GCM-SIV")
df_software_aes = extract_summary_data(data_software_aes, "Software AES-GCM-SIV")
df_software_ascon = extract_summary_data(data_software_ascon, "Software Ascon")

df_all = pd.concat([df_hardware, df_software_aes, df_software_ascon], ignore_index=True)

# 文件大小排序映射
file_size_order = ['256B', '1KB', '4KB', '16KB', '64KB', '200KB', '400KB', '800KB', '1MB', '4MB', '16MB']
file_size_mapping = {size: i for i, size in enumerate(file_size_order)}
df_all['file_size_order'] = df_all['file_name'].map(file_size_mapping)
df_all = df_all.sort_values('file_size_order')

# 定义配色方案
colors = ['#2E86AB', '#A23B72', '#F18F01']

# 修改第一张大图的代码部分：
fig1 = plt.figure(figsize=(16, 12))

# 项目名称简写映射（与第二张大图保持一致）
project_short_names = {
    "Hardware AES-GCM-SIV": "Hardware AES",
    "Software AES-GCM-SIV": "Software AES",
    "Software Ascon": "Software Ascon"
}

# 子图1: 加密吞吐量对比
ax1 = plt.subplot(3, 1, 1)
for i, project in enumerate(df_all['project'].unique()):
    project_data = df_all[df_all['project'] == project]
    short_name = project_short_names[project]
    ax1.plot(project_data['file_name'], project_data['avg_encryption_throughput'], 
             marker='o', label=short_name, linewidth=2, color=colors[i])
ax1.set_xlabel('File Size', fontsize=12)
ax1.set_ylabel('Encryption Throughput (B/s)', fontsize=12)  # 修改单位
ax1.set_title('Encryption Throughput Comparison', fontsize=14, fontweight='bold')
ax1.tick_params(axis='x', rotation=45)
ax1.legend(loc='upper left')
ax1.grid(True, alpha=0.3)

# 子图2: 解密吞吐量对比
ax2 = plt.subplot(3, 1, 2)
for i, project in enumerate(df_all['project'].unique()):
    project_data = df_all[df_all['project'] == project]
    short_name = project_short_names[project]
    ax2.plot(project_data['file_name'], project_data['avg_decryption_throughput'], 
             marker='s', label=short_name, linewidth=2, color=colors[i])
ax2.set_xlabel('File Size', fontsize=12)
ax2.set_ylabel('Decryption Throughput (B/s)', fontsize=12)  # 修改单位
ax2.set_title('Decryption Throughput Comparison', fontsize=14, fontweight='bold')
ax2.tick_params(axis='x', rotation=45)
ax2.legend(loc='upper left')
ax2.grid(True, alpha=0.3)

# 子图3: 总吞吐量对比
ax3 = plt.subplot(3, 1, 3)
for i, project in enumerate(df_all['project'].unique()):
    project_data = df_all[df_all['project'] == project]
    short_name = project_short_names[project]
    ax3.plot(project_data['file_name'], project_data['avg_total_throughput'], 
             marker='^', label=short_name, linewidth=2, color=colors[i])
ax3.set_xlabel('File Size', fontsize=12)
ax3.set_ylabel('Total Throughput (B/s)', fontsize=12)  # 修改单位
ax3.set_title('Total Throughput Comparison', fontsize=14, fontweight='bold')
ax3.tick_params(axis='x', rotation=45)
ax3.legend(loc='upper left')
ax3.grid(True, alpha=0.3)

plt.suptitle('Performance Comparison: Hardware AES vs Software AES vs Software Ascon', 
             fontsize=16, fontweight='bold', y=0.98)  # 修改标题，使用简写名称
plt.tight_layout()

# 创建第二张大图：综合性能分析，包含6个子图
fig2 = plt.figure(figsize=(20, 12))
gs = GridSpec(2, 3, figure=fig2, hspace=0.35, wspace=0.35)

# 项目名称简写映射
project_short_names = {
    "Hardware AES-GCM-SIV": "Hardware AES",
    "Software AES-GCM-SIV": "Software AES",
    "Software Ascon": "Software Ascon"
}

# 子图1: 不同文件大小下的总吞吐量折线图
ax1 = fig2.add_subplot(gs[0, 0])
for i, project in enumerate(df_all['project'].unique()):
    project_data = df_all[df_all['project'] == project]
    short_name = project_short_names[project]
    ax1.plot(project_data['file_name'], project_data['avg_total_throughput'], 
             marker='o', label=short_name, linewidth=2.5, color=colors[i])
    # 添加数据标签（选择性显示）
    for j, (x, y) in enumerate(zip(project_data['file_name'], project_data['avg_total_throughput'])):
        if j % 3 == 0:  # 避免标签过于密集
            ax1.annotate(f'{y:.0f}', (x, y), textcoords="offset points", xytext=(0,10), 
                        ha='center', fontsize=8, color=colors[i])
ax1.set_xlabel('File Size', fontsize=11)
ax1.set_ylabel('Total Throughput (B/s)', fontsize=11)
ax1.set_title('Total Throughput by File Size', fontsize=12, fontweight='bold')
ax1.tick_params(axis='x', rotation=45)
ax1.legend(fontsize=9, loc='upper left')
ax1.grid(True, alpha=0.3)

# 子图2: 小文件稳定性分析（256B, 1KB, 4KB, 16KB, 64KB）
ax2 = fig2.add_subplot(gs[0, 1])
small_files = ['256B', '1KB', '4KB', '16KB', '64KB']
small_data = df_all[df_all['file_name'].isin(small_files)]

for i, project in enumerate(df_all['project'].unique()):
    project_data = small_data[small_data['project'] == project]
    short_name = project_short_names[project]
    # 使用总吞吐量的标准差作为稳定性指标
    ax2.plot(project_data['file_name'], project_data['std_total_throughput'], 
             marker='s', linewidth=2.5, label=short_name, color=colors[i])
    # 添加数据标签
    for j, (x, y) in enumerate(zip(project_data['file_name'], project_data['std_total_throughput'])):
        ax2.annotate(f'{y:.2f}', (x, y), textcoords="offset points", xytext=(0,8), 
                    ha='center', fontsize=8, color=colors[i])

ax2.set_xlabel('File Size', fontsize=11)
ax2.set_ylabel('Standard Deviation (B/s)', fontsize=11)
ax2.set_title('Small File Stability Analysis', fontsize=12, fontweight='bold')
ax2.tick_params(axis='x', rotation=45)
ax2.legend(fontsize=9)
ax2.grid(True, alpha=0.3)

# 子图3: 平均性能柱状图
ax3 = fig2.add_subplot(gs[0, 2])
# 计算每个项目的平均性能
projects = df_all['project'].unique()
avg_performance = df_all.groupby('project').agg({
    'avg_encryption_throughput': 'mean',
    'avg_decryption_throughput': 'mean',
    'avg_total_throughput': 'mean'
}).reset_index()

x = np.arange(len(projects))
bar_width = 0.25

# 计算加密、解密、总吞吐量的平均值
enc_avg = avg_performance['avg_encryption_throughput'].values
dec_avg = avg_performance['avg_decryption_throughput'].values
total_avg = avg_performance['avg_total_throughput'].values

bars1 = ax3.bar(x - bar_width, enc_avg, bar_width, label='Encryption', color=colors[0], alpha=0.8)
bars2 = ax3.bar(x, dec_avg, bar_width, label='Decryption', color=colors[1], alpha=0.8)
bars3 = ax3.bar(x + bar_width, total_avg, bar_width, label='Total', color=colors[2], alpha=0.8)

ax3.set_xlabel('Algorithm', fontsize=11)
ax3.set_ylabel('Average Throughput (B/s)', fontsize=11)
ax3.set_title('Average Performance Comparison', fontsize=12, fontweight='bold')
ax3.set_xticks(x)
ax3.set_xticklabels([project_short_names[p] for p in projects], rotation=15)
ax3.legend(fontsize=9, loc='lower left')
ax3.grid(True, alpha=0.3, axis='y')

# 添加数值标签
for bars in [bars1, bars2, bars3]:
    for bar in bars:
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height + 20,
                 f'{height:.0f}', ha='center', va='bottom', fontsize=8)

# 子图4: 资源占用情况柱状图
ax4 = fig2.add_subplot(gs[1, 0])

resources = ['Flash', 'RAM', 'Code Size']
resource_labels = ['Flash (KB)', 'RAM (KB)', 'Code Size (KB)']
projects = list(resource_data.keys())

# 提取数据
flash_values = [resource_data[p]['Flash'] for p in projects]
ram_values = [resource_data[p]['RAM'] for p in projects]
code_values = [resource_data[p]['Code Size'] for p in projects]

# 重新组织数据结构
resource_matrix = {
    'Flash': flash_values,
    'RAM': ram_values,
    'Code Size': code_values
}

x = np.arange(len(resources))  # x位置：0=Flash, 1=RAM, 2=Code Size
bar_width = 0.25

# 为每个项目绘制柱状图
for i, project in enumerate(projects):
    values = [resource_matrix[resource][i] for resource in resources]
    short_name = project_short_names[project]
    ax4.bar(x + (i - 1) * bar_width, values, bar_width, 
            label=short_name, color=colors[i], alpha=0.8)

ax4.set_xlabel('Resource Type', fontsize=11)
ax4.set_ylabel('Size (KB)', fontsize=11)
ax4.set_title('Resource Usage Comparison', fontsize=12, fontweight='bold')
ax4.set_xticks(x)
ax4.set_xticklabels(resource_labels)
ax4.legend(fontsize=9, loc='upper center')
ax4.grid(True, alpha=0.3, axis='y')

# 添加数值标签 - 居中显示
for i, resource in enumerate(resources):
    for j, project in enumerate(projects):
        value = resource_matrix[resource][j]
        # 计算柱状图的中心位置
        bar_center_x = x[i] + (j - 1) * bar_width
        bar_height = value
        # 在柱状图中心位置上方添加标签
        ax4.text(bar_center_x, bar_height + 0.5, 
                 f'{value:.2f}', ha='center', va='bottom', fontsize=8)
        
# 子图5: 总平均吞吐量排行榜柱状图
ax5 = fig2.add_subplot(gs[1, 1])

# 计算每个项目的总平均吞吐量并排序
avg_total_by_project = df_all.groupby('project')['avg_total_throughput'].mean().reset_index()
avg_total_by_project = avg_total_by_project.sort_values('avg_total_throughput', ascending=False)

# 分配颜色和排名
rank_colors = ['gold', 'silver', '#CD7F32']  # 金、银、铜
sorted_projects = avg_total_by_project['project'].tolist()
sorted_throughputs = avg_total_by_project['avg_total_throughput'].tolist()

# 使用简写名称
short_sorted_projects = [project_short_names[p] for p in sorted_projects]

bars = ax5.barh(short_sorted_projects, sorted_throughputs, color=rank_colors)
ax5.set_xlabel('Average Total Throughput (B/s)', fontsize=11)
ax5.set_title('Performance Ranking', fontsize=12, fontweight='bold')
ax5.grid(True, alpha=0.3, axis='x')

# 添加排名标签和数值
for i, (bar, project, throughput) in enumerate(zip(bars, short_sorted_projects, sorted_throughputs)):
    width = bar.get_width()
    rank_text = f'#{i+1}'
    ax5.text(width + 50, bar.get_y() + bar.get_height()/2, 
             f'{rank_text}: {width:.0f} B/s', 
             va='center', ha='left', fontsize=10, fontweight='bold')

# 子图6: 雷达图综合性能评分
ax6 = fig2.add_subplot(gs[1, 2], polar=True)

# 雷达图指标：吞吐量、稳定性、代码效率、资源效率
categories = ['Throughput', 'Stability', 'Code Efficiency', 'RAM Efficiency', 'Flash Efficiency']
N = len(categories)

# 计算每个项目的指标
projects = df_all['project'].unique()

# 1. 吞吐量（使用总平均吞吐量）
throughputs = [df_all[df_all['project'] == p]['avg_total_throughput'].mean() for p in projects]

# 2. 稳定性（使用所有文件的标准差平均值，越低越好）
stabilities = []
for p in projects:
    project_data = df_all[df_all['project'] == p]
    stability = project_data['std_total_throughput'].mean()
    stabilities.append(stability)

# 3. 代码效率（代码大小越小越好）
code_sizes = [resource_data[p]['Code Size'] for p in projects]

# 4. RAM效率（RAM使用越小越好）
ram_usages = [resource_data[p]['RAM'] for p in projects]

# 5. Flash效率（Flash使用越小越好）
flash_usages = [resource_data[p]['Flash'] for p in projects]

# 重整化处理：每个维度上最大值对应1，其余按比例调整
def normalize_by_max(values, higher_better=True):
    if not higher_better:
        # 对于越低越好的指标，先取倒数
        values = [1/(v+0.001) for v in values]  # 加0.001避免除以0
    
    max_val = max(values)
    if max_val == 0:
        return [0 for _ in values]
    
    # 重整化：最大值归一化为1，其他按比例调整
    return [v/max_val for v in values]

# 归一化处理
throughput_norm = normalize_by_max(throughputs, higher_better=True)
stability_norm = normalize_by_max(stabilities, higher_better=False)  # 稳定性是越低越好
code_eff_norm = normalize_by_max(code_sizes, higher_better=False)    # 代码大小越小越好
ram_eff_norm = normalize_by_max(ram_usages, higher_better=False)     # RAM使用越小越好
flash_eff_norm = normalize_by_max(flash_usages, higher_better=False) # Flash使用越小越好

# 组合数据
values = list(zip(throughput_norm, stability_norm, code_eff_norm, ram_eff_norm, flash_eff_norm))

angles = [n / float(N) * 2 * np.pi for n in range(N)]
angles += angles[:1]

for i, project in enumerate(projects):
    algo_values = values[i]
    algo_values += algo_values[:1]
    short_name = project_short_names[project]
    ax6.plot(angles, algo_values, 'o-', linewidth=2, label=short_name, color=colors[i])
    ax6.fill(angles, algo_values, alpha=0.1, color=colors[i])

ax6.set_xticks(angles[:-1])
ax6.set_xticklabels(categories, fontsize=10)
ax6.set_ylim(0, 1)
ax6.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
ax6.set_title('Comprehensive Performance Radar Chart', fontsize=12, fontweight='bold', pad=20)
ax6.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0), fontsize=9)
ax6.grid(True)

plt.suptitle('Comprehensive Performance Analysis: Hardware AES vs Software AES vs Software Ascon', 
             fontsize=16, fontweight='bold', y=0.98)
plt.tight_layout()

# 显示图形
plt.show()

# 输出统计分析
print("="*80)
print("COMPREHENSIVE STATISTICAL ANALYSIS")
print("="*80)

for project in df_all['project'].unique():
    project_data = df_all[df_all['project'] == project]
    short_name = project_short_names[project]
    print(f"\n{short_name}:")
    print(f"  Average Encryption Throughput: {project_data['avg_encryption_throughput'].mean():.2f} B/s")
    print(f"  Average Decryption Throughput: {project_data['avg_decryption_throughput'].mean():.2f} B/s")
    print(f"  Average Total Throughput: {project_data['avg_total_throughput'].mean():.2f} B/s")
    print(f"  Resource Usage - Flash: {resource_data[project]['Flash']} KB, RAM: {resource_data[project]['RAM']} KB, Code Size: {resource_data[project]['Code Size']} KB")
    
    # 性能提升对比
    if project != 'Hardware AES-GCM-SIV':
        baseline = df_all[df_all['project'] == 'Hardware AES-GCM-SIV']['avg_total_throughput'].mean()
        current = project_data['avg_total_throughput'].mean()
        improvement = (current - baseline) / baseline * 100
        print(f"  Performance Improvement vs Hardware AES: {improvement:.2f}%")

print("\n" + "="*80)
print("KEY FINDINGS:")
print("1. Software Ascon performs best for large file processing")
print("2. Hardware AES has advantage in small file encryption")
print("3. Software AES has best code efficiency (smallest size)")
print("4. All algorithms show good stability (low standard deviation)")
print("5. Software Ascon has the highest overall throughput but largest code size")
print("="*80)