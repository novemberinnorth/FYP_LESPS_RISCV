# fixed_elf_analysis.py
import subprocess
import os
import re

class FixedELFAnalyzer:
    def __init__(self):
        self.sections = {}
    
    def parse_readelf_file(self, elf_path):
        """直接解析ELF文件"""
        try:
            result = subprocess.run(
                ['readelf', '-S', elf_path],
                capture_output=True, 
                text=True, 
                check=True
            )
            return self.parse_readelf_output(result.stdout)
        except Exception as e:
            print(f"解析ELF文件失败: {e}")
            return None
    
    def parse_readelf_output(self, output_text):
        """解析readelf输出 - 修正版本"""
        lines = output_text.split('\n')
        parsing = False
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('[Nr]'):
                parsing = True
                continue
            
            if not parsing or not line:
                continue
                
            # 解析段信息
            match = re.match(r'\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', line)
            if match:
                nr, name, type_, addr, offset, size = match.groups()
                
                # 转换为十进制
                size_dec = int(size, 16)
                addr_dec = int(addr, 16) if addr != '00000000' else 0
                
                self.sections[name] = {
                    'name': name,
                    'type': type_,
                    'address': addr_dec,
                    'size': size_dec,
                    'size_hex': size,
                    'flags': self._extract_flags(line)
                }
        return True
    
    def _extract_flags(self, line):
        """提取段标志"""
        flags = ''
        if 'A' in line: flags += 'A'  # Alloc
        if 'X' in line: flags += 'X'  # Execute  
        if 'W' in line: flags += 'W'  # Write
        return flags
    
    def analyze_with_fixed_logic(self):
        """使用修正的逻辑分析资源"""
        flash_total = 0
        ram_total = 0
        code_size = 0
        
        # 明确的段分类
        flash_sections = ['.init', '.text', '.rodata', '.lalign']
        ram_sections = ['.data', '.bss', '.heap', '.stack', '.dalign']
        
        for name, info in self.sections.items():
            if info['size'] == 0:
                continue
                
            # 基于段名分类
            if any(flash_section in name for flash_section in flash_sections):
                flash_total += info['size']
                if '.text' in name or '.init' in name:
                    code_size += info['size']
            elif any(ram_section in name for ram_section in ram_sections):
                ram_total += info['size']
            elif name.startswith('.debug'):
                # 调试信息，不计入
                pass
            else:
                # 未知段，根据地址判断
                if info['address'] >= 0x08000000 and info['address'] < 0x20000000:
                    flash_total += info['size']
                elif info['address'] >= 0x20000000:
                    ram_total += info['size']
        
        return {
            'flash_kb': flash_total / 1024,
            'ram_kb': ram_total / 1024, 
            'code_size_kb': code_size / 1024,
            'flash_bytes': flash_total,
            'ram_bytes': ram_total
        }

def analyze_all_elfs_fixed(elf_paths):
    """使用修正逻辑分析所有ELF文件"""
    results = {}
    
    for name, path in elf_paths.items():
        if os.path.exists(path):
            print(f"\n🔍 分析 {name}: {path}")
            
            analyzer = FixedELFAnalyzer()
            if analyzer.parse_readelf_file(path):
                resources = analyzer.analyze_with_fixed_logic()
                results[name] = resources
                print(f"  ✅ Flash: {resources['flash_kb']:.2f} KB")
                print(f"  ✅ RAM: {resources['ram_kb']:.2f} KB")
                print(f"  ✅ 代码大小: {resources['code_size_kb']:.2f} KB")
            else:
                print(f"  ❌ 分析失败")
                results[name] = None
        else:
            print(f"  ❌ 文件不存在: {path}")
            results[name] = None
    
    return results

# 使用修正的分析
elf_files = {
    'AES_Hardware': 'D:/My_Workspace/NucleiStudio_workspace/AES_hardware/Debug/AES_hardware.elf',
    'AES_Software': 'D:/My_Workspace/NucleiStudio_workspace/AES_software/Debug/AES_software.elf',
    'Ascon_Software': 'D:/My_Workspace/NucleiStudio_workspace/Ascon_software/Debug/Ascon_software.elf'
}

print("🚀 运行修正后的ELF分析...")
corrected_results = analyze_all_elfs_fixed(elf_files)

# 生成修正报告
print(f"\n{'='*60}")
print("📊 修正后的资源占用对比")
print(f"{'='*60}")
print(f"{'算法':<20} {'Flash(KB)':<12} {'RAM(KB)':<12} {'代码大小(KB)':<15} {'总资源(KB)':<15}")
print(f"{'-'*20} {'-'*12} {'-'*12} {'-'*15} {'-'*15}")

for name, data in corrected_results.items():
    if data:
        total_resource = data['flash_kb'] + data['ram_kb']
        print(f"{name:<20} {data['flash_kb']:<12.2f} {data['ram_kb']:<12.2f} {data['code_size_kb']:<15.2f} {total_resource:<15.2f}")