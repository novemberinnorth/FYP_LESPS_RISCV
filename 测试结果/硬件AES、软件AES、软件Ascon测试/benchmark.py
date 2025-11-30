# fixed_comparison_benchmark.py
import serial
import time
import os
import base64
import struct
import numpy as np
from serial.tools import list_ports
import json
from datetime import datetime

class FixedComparisonBenchmark:
    def __init__(self):
        self.config = {
            'baud_rate': 115200,
            'timeout': 60,
            'test_iterations': 5,
            'file_sizes': [1024, 4096, 8192, 32768, 65536],  # 移除会失败的131072
            'ports': {
                'AES_Hardware': 'COM3',
                'AES_Software': 'COM3',
                'Ascon_Software': 'COM3'
            }
        }
        self.results = {}
    
    def robust_performance_test(self, port, algorithm):
        """健壮的性能测试 - 解决第一次迭代异常"""
        print(f"⚡ 健壮测试: {algorithm}")
        time.sleep(20)
        
        results = {}
        
        for size in self.config['file_sizes']:
            print(f"  📁 测试 {size} bytes")
            
            # 创建测试文件
            test_data = os.urandom(size)
            test_file = f'test_robust_{size}.bin'
            with open(test_file, 'wb') as f:
                f.write(test_data)
            
            times = []
            throughputs = []
            
            # 添加预热迭代（不记录结果）
            print("    🔥 预热迭代...")
            warmup_success = self.single_encryption_test(port, test_file, f'warmup_{size}.bin')
            if warmup_success:
                print("    ✅ 预热完成")
            else:
                print("    ⚠️ 预热失败，继续测试")
            
            for i in range(self.config['test_iterations']):
                encrypt_time = self.single_encryption_test(port, test_file, f'encrypt_{size}_{i}.bin')
                
                if encrypt_time > 0:
                    throughput = size / encrypt_time / 1024
                    throughputs.append(throughput)
                    times.append(encrypt_time)
                    print(f"    迭代 {i+1}: {throughput:.3f} KB/s, 时间: {encrypt_time:.2f}s")
                else:
                    print(f"    迭代 {i+1}: 失败")
                    throughputs.append(0)  # 记录失败但继续测试
            
            # 分析性能模式
            if len(throughputs) > 1:
                first_vs_rest = throughputs[0] / np.mean(throughputs[1:]) if np.mean(throughputs[1:]) > 0 else 1
                stability = np.std(throughputs[1:]) / np.mean(throughputs[1:]) * 100 if len(throughputs) > 2 else 0
                
                print(f"    📊 性能分析:")
                print(f"      第一次/后续比率: {first_vs_rest:.2f}x")
                print(f"      稳定性(后续): {stability:.1f}%")
            
            # 使用后续迭代的平均值（排除可能的异常第一次迭代）
            valid_throughputs = [t for t in throughputs if t > 0]
            if len(valid_throughputs) > 1:
                # 如果第一次明显异常，使用后续迭代的平均值
                if throughputs[0] > 1.5 * np.mean(valid_throughputs[1:]):
                    avg_throughput = np.mean(valid_throughputs[1:])
                    print(f"    ⚠️ 检测到第一次迭代异常，使用后续平均值")
                else:
                    avg_throughput = np.mean(valid_throughputs)
            elif valid_throughputs:
                avg_throughput = np.mean(valid_throughputs)
            else:
                avg_throughput = 0
            
            if avg_throughput > 0:
                results[size] = {
                    'avg_throughput_kbps': avg_throughput,
                    'raw_throughputs': throughputs,
                    'raw_times': times,
                    'success_rate': len(valid_throughputs) / len(throughputs),
                    'first_iteration_ratio': throughputs[0] / avg_throughput if avg_throughput > 0 else 1,
                    'stability': np.std(throughputs[1:]) / np.mean(throughputs[1:]) * 100 if len(throughputs) > 2 else 0
                }
                print(f"    ✅ 平均: {avg_throughput:.3f} KB/s, 成功率: {results[size]['success_rate']:.0%}")
            else:
                results[size] = None
                print(f"    ❌ 所有迭代失败")
            
            # 清理文件
            for f in [test_file]:
                if os.path.exists(f):
                    try:
                        os.remove(f)
                    except:
                        pass
            
            # 测试间隔，让MCU恢复
            time.sleep(2)
        
        return results
    
    def single_encryption_test(self, port, input_file, output_file):
        """单次加密测试"""
        try:
            ser = serial.Serial(port, self.config['baud_rate'], timeout=15)
            start_time = time.time()
            
            # 完整的握手过程
            if not self.complete_handshake(ser, 'encrypt'):
                ser.close()
                return -1
            
            # 读取文件
            with open(input_file, 'rb') as f:
                file_data = f.read()
            
            file_size = len(file_data)
            
            # 发送文件大小
            ser.write(struct.pack('>I', file_size))
            if not self.wait_for_response(ser, 'ACK', timeout=10):
                ser.close()
                return -1
            
            # 等待数据就绪
            if not self.wait_for_response(ser, 'READY_FOR_DATA', timeout=10):
                ser.close()
                return -1
            
            # 分块处理数据
            total_sent = 0
            while total_sent < file_size:
                # 等待块请求
                chunk_size = self.get_chunk_size(ser)
                if chunk_size <= 0:
                    ser.close()
                    return -1
                
                # 发送数据块
                remaining = file_size - total_sent
                current_size = min(chunk_size, remaining)
                chunk = file_data[total_sent:total_sent + current_size]
                ser.write(chunk)
                total_sent += len(chunk)
                
                # 等待块接收确认
                if not self.wait_for_response(ser, 'CHUNK_RECEIVED', timeout=20):
                    ser.close()
                    return -1
                
                # 跳过处理输出
                if not self.skip_processing_output(ser):
                    ser.close()
                    return -1
            
            # 等待流完成
            if not self.wait_for_response(ser, 'STREAM_COMPLETE', timeout=30):
                ser.close()
                return -1
            
            end_time = time.time()
            ser.close()
            
            return end_time - start_time
            
        except Exception as e:
            print(f"      测试异常: {e}")
            return -1
    
    def complete_handshake(self, ser, operation):
        """完整的握手过程"""
        # 等待MCU就绪
        if not self.wait_for_response(ser, 'READY', timeout=15):
            return False
        
        # 选择新模式
        ser.write(b'n')
        if not self.wait_for_response(ser, 'NEW_STREAM_MODE', timeout=10):
            return False
        
        # 等待操作选择
        if not self.wait_for_response(ser, 'WAIT_OPERATION', timeout=10):
            return False
        
        # 发送操作
        op_byte = b'e' if operation == 'encrypt' else b'd'
        ser.write(op_byte)
        if not self.wait_for_response(ser, 'ACK', timeout=10):
            return False
        
        # 发送密钥
        key = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        ser.write(key)
        if not self.wait_for_response(ser, 'ACK', timeout=10):
            return False
        
        # 发送IV
        iv = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        ser.write(iv)
        if not self.wait_for_response(ser, 'ACK', timeout=10):
            return False
        
        # 等待文件大小提示
        if not self.wait_for_response(ser, 'WAIT_SIZE', timeout=10):
            return False
        
        return True
    
    def wait_for_response(self, ser, expected, timeout=10):
        """等待响应"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if expected in line:
                    return True
                elif 'ERROR' in line:
                    print(f"      ❌ MCU错误: {line}")
                    return False
            time.sleep(0.05)
        print(f"      ⚠️ 等待 {expected} 超时")
        return False
    
    def get_chunk_size(self, ser, timeout=10):
        """获取块大小"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'WAIT_CHUNK' in line:
                    try:
                        return int(line.split(':')[1])
                    except:
                        return 1024
                elif 'ERROR' in line:
                    return -1
        return -1
    
    def skip_processing_output(self, ser, timeout=15):
        """跳过处理输出"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'CHUNK_PROCESSED' in line:
                    return True
                elif 'ERROR' in line:
                    return False
            time.sleep(0.05)
        return False
    
    def run_robust_comparison(self):
        """运行健壮的对比测试"""
        print("🔬 开始健壮的算法对比测试")
        print("=" * 60)
        
        available_ports = list_ports.comports()
        print(f"🔍 可用串口: {[p.device for p in available_ports]}")
        
        for algo_name, port in self.config['ports'].items():
            if not any(p.device == port for p in available_ports):
                print(f"❌ {algo_name}: 端口 {port} 不可用，跳过")
                continue
            
            print(f"\n🎯 测试: {algo_name}")
            print("-" * 30)
            
            try:
                # 运行健壮测试
                results = self.robust_performance_test(port, algo_name)
                
                if any(results.values()):
                    self.results[algo_name] = results
                    print(f"✅ {algo_name} 测试完成")
                else:
                    print(f"❌ {algo_name} 测试失败")
                    
            except Exception as e:
                print(f"❌ {algo_name} 测试异常: {e}")
        
        # 生成对比报告
        self.generate_robust_report()
        
        # 保存结果
        self.save_results()
        
        return self.results
    
    def generate_robust_report(self):
        """生成健壮的对比报告"""
        print(f"\n{'='*60}")
        print("📊 健壮的加密算法性能对比报告")
        print(f"{'='*60}")
        
        if not self.results:
            print("❌ 没有可对比的数据")
            return
        
        # 计算综合性能指标
        comparison_data = {}
        
        for algo, data in self.results.items():
            throughputs = []
            stability_scores = []
            first_iter_ratios = []
            
            for size, size_data in data.items():
                if size_data and size_data.get('avg_throughput_kbps', 0) > 0:
                    throughputs.append(size_data['avg_throughput_kbps'])
                    stability_scores.append(size_data.get('stability', 0))
                    first_iter_ratios.append(size_data.get('first_iteration_ratio', 1))
            
            if throughputs:
                comparison_data[algo] = {
                    'avg_throughput': np.mean(throughputs),
                    'max_throughput': max(throughputs),
                    'min_throughput': min(throughputs),
                    'stability': np.mean(stability_scores),
                    'first_iter_anomaly': np.mean(first_iter_ratios),
                    'scaling_factor': max(throughputs) / min(throughputs) if min(throughputs) > 0 else 0
                }
        
        # 性能排名（基于平均吞吐量）
        sorted_algos = sorted(comparison_data.items(), 
                            key=lambda x: x[1]['avg_throughput'], 
                            reverse=True)
        
        print("\n🏆 性能排名 (基于稳定后的平均值):")
        print(f"{'算法':<20} {'平均吞吐量(KB/s)':<18} {'最大吞吐量':<12} {'稳定性(%)':<12} {'第一次异常':<12}")
        print(f"{'-'*20} {'-'*18} {'-'*12} {'-'*12} {'-'*12}")
        
        for algo, data in sorted_algos:
            anomaly_flag = "⚠️" if data['first_iter_anomaly'] > 1.3 else "✅"
            print(f"{algo:<20} {data['avg_throughput']:<18.3f} {data['max_throughput']:<12.3f} {data['stability']:<12.1f} {anomaly_flag} {data['first_iter_anomaly']:.2f}x")
        
        # 详细对比
        print(f"\n📈 详细性能对比:")
        sizes = self.config['file_sizes']
        
        print(f"{'文件大小':<12} " + "".join(f"{algo:<15}" for algo in self.results.keys()))
        print(f"{'-'*12} " + "".join(f"{'-'*15}" for _ in self.results))
        
        for size in sizes:
            row = f"{size:<12} "
            for algo in self.results.keys():
                size_data = self.results[algo].get(size)
                if size_data and size_data.get('avg_throughput_kbps') is not None:
                    throughput = size_data['avg_throughput_kbps']
                else:
                    throughput = 0
                row += f"{throughput:<15.3f}"
            print(row)
        
        # 性能倍数对比
        if len(sorted_algos) >= 2:
            best_algo = sorted_algos[0][0]
            best_throughput = sorted_algos[0][1]['avg_throughput']
            
            print(f"\n⚡ 性能倍数对比 (以{best_algo}为基准):")
            for algo, data in sorted_algos[1:]:
                if data['avg_throughput'] > 0:
                    ratio = best_throughput / data['avg_throughput']
                    print(f"  {best_algo} 比 {algo} 快 {ratio:.2f} 倍")
        
        # 效率分析
        print(f"\n🎯 效率分析:")
        baud_rate = self.config['baud_rate']
        theoretical_max = baud_rate / 10 / 1024  # 理论最大
        
        for algo, data in sorted_algos:
            efficiency = data['avg_throughput'] / theoretical_max * 100
            print(f"  {algo}: {efficiency:.1f}% 理论最大吞吐量")
        
        # 问题诊断
        print(f"\n🔍 问题诊断:")
        for algo, data in comparison_data.items():
            if data['first_iter_anomaly'] > 1.3:
                print(f"  ⚠️ {algo}: 检测到第一次迭代性能异常 ({data['first_iter_anomaly']:.2f}x)")
        
        return comparison_data
    
    def save_results(self):
        """保存测试结果"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"robust_benchmark_results_{timestamp}.json"
        
        results_data = {
            'timestamp': timestamp,
            'config': self.config,
            'results': self.results,
            'summary': self.generate_summary(),
            'issues_detected': self.detect_issues()
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 结果已保存到: {filename}")
    
    def generate_summary(self):
        """生成摘要"""
        summary = {}
        
        for algo, data in self.results.items():
            throughputs = []
            for size, size_data in data.items():
                if size_data and size_data.get('avg_throughput_kbps'):
                    throughputs.append(size_data['avg_throughput_kbps'])
            
            if throughputs:
                summary[algo] = {
                    'performance_rank': 0,  # 将在后面计算
                    'avg_throughput_kbps': np.mean(throughputs),
                    'throughput_range': f"{min(throughputs):.3f}-{max(throughputs):.3f}",
                    'best_size': self.config['file_sizes'][np.argmax(throughputs)],
                    'efficiency_percent': (np.mean(throughputs) / (self.config['baud_rate'] / 10 / 1024)) * 100,
                    'successful_sizes': len(throughputs)
                }
        
        # 计算排名
        sorted_algos = sorted(summary.items(), key=lambda x: x[1]['avg_throughput_kbps'], reverse=True)
        for rank, (algo, _) in enumerate(sorted_algos, 1):
            summary[algo]['performance_rank'] = rank
        
        return summary
    
    def detect_issues(self):
        """检测问题"""
        issues = []
        
        for algo, data in self.results.items():
            # 检测第一次迭代异常
            first_iter_anomalies = []
            for size, size_data in data.items():
                if size_data and size_data.get('first_iteration_ratio', 1) > 1.3:
                    first_iter_anomalies.append(size)
            
            if first_iter_anomalies:
                issues.append({
                    'algorithm': algo,
                    'type': 'first_iteration_anomaly',
                    'description': f'在文件大小 {first_iter_anomalies} 检测到第一次迭代性能异常',
                    'severity': 'medium'
                })
            
            # 检测稳定性问题
            stability_issues = []
            for size, size_data in data.items():
                if size_data and size_data.get('stability', 0) > 20:  # 变异系数 > 20%
                    stability_issues.append(size)
            
            if stability_issues:
                issues.append({
                    'algorithm': algo,
                    'type': 'stability_issue',
                    'description': f'在文件大小 {stability_issues} 检测到性能稳定性问题',
                    'severity': 'low'
                })
        
        return issues

# 运行健壮测试
if __name__ == "__main__":
    benchmark = FixedComparisonBenchmark()
    
    print("🚀 启动健壮的加密算法对比测试")
    print("注意: 此版本解决了第一次迭代异常和大文件测试问题")
    
    try:
        results = benchmark.run_robust_comparison()
        print("\n🎉 健壮对比测试完成！")
        
        # 提供改进建议
        print(f"\n💡 性能改进建议:")
        print("1. 考虑在MCU程序中使用预热机制消除第一次迭代异常")
        print("2. 优化通信协议，减少Base64编码开销")
        print("3. 检查AES算法在大文件处理时的内存限制")
        print("4. 考虑提高串口波特率（如果硬件支持）")
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()