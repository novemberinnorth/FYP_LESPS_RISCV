import serial
import time
import os
import base64
import struct
import secrets
import sys

BaudRate = 115200
CHUNK_SIZE = 1024
default_input = "1.txt"
default_ciphertext = "encrypted.bin"
default_output = "output.txt"

def hex_string_to_bytes(hex_str):
    """将16进制字符串转换为字节"""
    try:
        # 移除可能的空格和0x前缀
        hex_str = hex_str.strip().replace(' ', '').replace('0x', '').replace('0X', '')
        if len(hex_str) == 0:
            return None
        if len(hex_str) % 2 != 0:
            # 奇数长度，可能缺少前导0
            hex_str = '0' + hex_str
        return bytes.fromhex(hex_str)
    except Exception as e:
        print(f"错误: 无效的16进制字符串: {e}")
        return None

def get_user_key():
    """获取用户输入的密钥"""
    while True:
        key_input = input("输入16字节密钥(16进制, 32个字符, 如: 00112233445566778899AABBCCDDEEFF, 回车使用默认): ").strip()
        if key_input == "":
            # 使用默认密钥
            default_key = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
            print(f"使用默认密钥: {default_key.hex().upper()}")
            return default_key
        
        key_bytes = hex_string_to_bytes(key_input)
        if key_bytes is None:
            print("无效的密钥格式，请重新输入")
            continue
            
        if len(key_bytes) != 16:
            print(f"密钥长度必须为16字节，当前为{len(key_bytes)}字节")
            continue
            
        return key_bytes

def get_user_nonce():
    """获取用户输入的Nonce"""
    while True:
        nonce_input = input("输入16字节Nonce(16进制, 32个字符, 回车使用随机生成): ").strip()
        if nonce_input == "":
            # 随机生成
            nonce = secrets.token_bytes(16)
            print(f"使用随机Nonce: {nonce.hex().upper()}")
            return nonce
        
        nonce_bytes = hex_string_to_bytes(nonce_input)
        if nonce_bytes is None:
            print("无效的Nonce格式，请重新输入")
            continue
            
        if len(nonce_bytes) != 16:
            print(f"Nonce长度必须为16字节，当前为{len(nonce_bytes)}字节")
            continue
            
        return nonce_bytes

def get_user_aad():
    """获取用户输入的AAD"""
    while True:
        aad_input = input("输入AAD(16进制, 回车跳过): ").strip()
        if aad_input == "":
            return b""  # 空AAD
        
        aad_bytes = hex_string_to_bytes(aad_input)
        if aad_bytes is None:
            print("无效的AAD格式，请重新输入")
            continue
            
        return aad_bytes

class GCM_SIV_FileProcessor:
    def __init__(self, port, verbose=False, show_progress=True):
        self.port = port
        self.ser = None
        self.verbose = verbose
        self.show_progress = show_progress
        self.current_chunk = 0
        self.total_chunks = 0
        self.total_processed = 0
        self.total_size = 0
        
    def _update_progress(self):
        """更新进度显示"""
        if self.show_progress and self.total_size > 0:
            progress = (self.total_processed / self.total_size) * 100
            sys.stdout.write(f"\r[{progress:6.2f}%] Chunk {self.current_chunk}/{self.total_chunks}: {self.total_processed}/{self.total_size} bytes\n")
            sys.stdout.flush()

    def connect(self):
        """连接到串口设备"""
        try:
            self.ser = serial.Serial(self.port, BaudRate, timeout=10, dsrdtr=False,
                                   write_timeout=10, xonxoff=False, rtscts=False)
            if self.verbose:
                print(f"Connected to {self.port}")
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False
            
    def disconnect(self):
        """断开连接"""
        if self.ser and self.ser.is_open:
            self.ser.close()
            if self.verbose:
                print("Disconnected")
            
    def read_mcu_output(self, timeout=10):
        """读取MCU输出并显示"""
        start_time = time.time()
        output_lines = []
        while time.time() - start_time < timeout:
            if self.ser.in_waiting > 0:
                line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                if line:
                    if self.verbose:
                        print(f"MCU: {line}")
                    output_lines.append(line)
            else:
                time.sleep(0.01)
        return output_lines
        
    def wait_for_message(self, expected_msg, timeout=10):
        """等待特定消息 - 增强版本"""
        if self.verbose:
            print(f"Waiting for: {expected_msg}")
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.ser.in_waiting > 0:
                line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                if self.verbose:
                    print(f"MCU: {line}")
                if expected_msg in line:
                    return line
                if 'ERROR' in line:
                    print(f"MCU error: {line}")
                    return None
                if 'STREAM_COMPLETE' in line:
                    if self.verbose:
                        print("✓ Stream completed while waiting for other message")
                    return 'STREAM_COMPLETE'
                if 'END_OF_STREAM_RECEIVED' in line:
                    if self.verbose:
                        print("✓ End of stream received")
                    return 'END_OF_STREAM_RECEIVED'
            time.sleep(0.01)
        if self.verbose:
            print(f"Timeout waiting for: {expected_msg}")
        return None
        
    def send_and_wait(self, data, expected_response, timeout=10):
        """发送数据并等待响应"""
        if isinstance(data, str):
            data = data.encode()
        if self.verbose:
            print(f"Sending: {data[:min(50, len(data))]}{'...' if len(data) > 50 else ''}")
        self.ser.write(data)
        self.ser.flush()
        return self.wait_for_message(expected_response, timeout)
        
    def safe_base64_decode(self, b64_data):
        """安全的Base64解码"""
        try:
            # 移除所有可能的无效字符
            import re
            b64_data = re.sub(r'[^A-Za-z0-9+/=]', '', b64_data)
            
            # 确保长度是4的倍数
            padding_needed = (4 - len(b64_data) % 4) % 4
            b64_data += '=' * padding_needed
            
            # 验证Base64字符串格式
            if len(b64_data) < 4 or len(b64_data) % 4 != 0:
                if self.verbose:
                    print(f"Invalid Base64 length: {len(b64_data)}")
                return None
                
            # 尝试解码
            decoded = base64.b64decode(b64_data)
            return decoded
        except Exception as e:
            if self.verbose:
                print(f"Base64 decode error: {e}")
                print(f"Problematic data length: {len(b64_data)}")
            return None
    
    def send_streaming_chunk(self, chunk_data, is_last=False):
        """在流式模式下发送一个数据块（简化版）"""
        if not self.ser or not self.ser.is_open:
            print("Serial port not connected")
            return False
            
        # 发送块头（4字节长度，大端序）
        if is_last:
            # 发送结束标记
            chunk_header = struct.pack('>I', 0)
            if self.verbose:
                print("Sending end-of-stream marker (0-length chunk)")
            self.ser.write(chunk_header)
            self.ser.flush()
            return True
        else:
            chunk_header = struct.pack('>I', len(chunk_data))
            if self.verbose:
                print(f"Sending chunk header: {len(chunk_data)} bytes")
            self.ser.write(chunk_header)
            self.ser.flush()
            
            # 等待MCU的WAIT_STREAM_CHUNK响应
            wait_msg = self.wait_for_message('WAIT_STREAM_CHUNK', 10)
            if not wait_msg:
                if self.verbose:
                    print("Did not receive WAIT_STREAM_CHUNK")
                return False
                
            # 发送实际数据
            if self.verbose:
                print(f"Sending chunk data: {len(chunk_data)} bytes")
            self.ser.write(chunk_data)
            self.ser.flush()
            return True
    
    def encrypt_file(self, input_file, output_file, custom_key=None, custom_nonce=None, custom_aad=b""):
        """加密文件（仅支持流式模式）"""
        if not self.connect():
            return False
            
        try:
            # 读取输入文件
            with open(input_file, 'rb') as f:
                file_data = f.read()
                
            print(f"File size: {len(file_data)} bytes")
            
            # 初始化进度变量
            self.total_size = len(file_data)
            self.total_processed = 0
            self.current_chunk = 0
            self.total_chunks = (len(file_data) + CHUNK_SIZE - 1) // CHUNK_SIZE
            
            # 确定密钥
            if custom_key is None:
                key = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
                print(f"使用默认密钥: {key.hex().upper()}")
            else:
                key = custom_key
                print(f"使用自定义密钥: {key.hex().upper()}")
            
            # 确定Nonce
            if custom_nonce is None:
                nonce = secrets.token_bytes(16)
                print(f"使用随机Nonce: {nonce.hex().upper()}")
            else:
                nonce = custom_nonce
                print(f"使用自定义Nonce: {nonce.hex().upper()}")
            
            # 确定AAD
            aad = custom_aad
            if len(aad) > 0:
                print(f"使用AAD: {aad.hex().upper()} (长度: {len(aad)}字节)")
            else:
                print("未使用AAD")
            
            print(f"Starting encryption process (streaming mode)...")
            
            # 等待MCU准备
            if not self.wait_for_message('READY', 15):
                print("MCU not ready")
                return False
                
            # 进入流模式
            if not self.send_and_wait(b'n', 'NEW_STREAM_MODE'):
                return False
                
            # 等待操作选择
            if not self.wait_for_message('WAIT_OPERATION'):
                return False
                
            # 发送加密操作
            if not self.send_and_wait(b'e', 'ACK'):
                return False
                
            # 等待密钥请求
            if not self.wait_for_message('WAIT_KEY'):
                return False
                
            # 发送密钥
            if not self.send_and_wait(key, 'ACK'):
                return False
                
            # 等待Nonce请求  
            if not self.wait_for_message('WAIT_NONCE'):
                return False
                
            # 发送Nonce
            if not self.send_and_wait(nonce, 'ACK'):
                return False
                
            # 发送AAD长度
            print("WAIT_AAD_LEN")
            aad_len = len(aad)
            aad_len_data = struct.pack('>I', aad_len)
            if not self.send_and_wait(aad_len_data, 'ACK'):
                print("注意: MCU可能不支持AAD，继续处理...")
                # 即使不支持AAD也继续，MCU会忽略AAD
                
            # 发送AAD数据（如果有）
            if aad_len > 0:
                print("WAIT_AAD_DATA")
                if not self.send_and_wait(aad, 'ACK'):
                    print("注意: AAD发送失败，继续处理...")
                
            print("✓ Entered streaming mode")
            
            # 流式模式发送数据
            return self._encrypt_streaming(file_data, nonce, output_file)
                
        except Exception as e:
            print(f"Encryption error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.disconnect()
    
    def _encrypt_streaming(self, file_data, nonce, output_file):
        """流式模式加密 - 复用传统模式通信逻辑"""
        total_sent = 0
        chunk_count = 0
        encrypted_data = b''
        
        # 关键：在开始前给MCU一些预热时间（与传统模式相同）
        if self.verbose:
            print("Allowing MCU hardware warmup...")
        time.sleep(0.3)  # 300ms预热时间，与传统模式的自然延迟相当
        
        # 复用传统模式的通信循环
        while total_sent < len(file_data):
            chunk_count += 1
            self.current_chunk = chunk_count
            
            # 等待MCU的WAIT_CHUNK消息（与传统模式完全相同）
            chunk_line = None
            start_time = time.time()
            while time.time() - start_time < 30 and chunk_line is None:
                if self.ser.in_waiting > 0:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    if self.verbose:
                        print(f"MCU: {line}")
                    
                    if line.startswith('WAIT_CHUNK'):
                        chunk_line = line
                    elif 'ERROR' in line:
                        print(f"MCU error: {line}")
                        return False
                    elif 'STREAM_COMPLETE' in line:
                        if self.verbose:
                            print("✓ Stream completed unexpectedly")
                        return True
                time.sleep(0.01)
            
            if chunk_line is None:
                print("No chunk request received")
                return False
            
            # 解析请求的块大小
            try:
                requested_size = int(chunk_line.split(':')[1])
            except:
                requested_size = CHUNK_SIZE
            
            # 计算要发送的实际块大小
            remaining = len(file_data) - total_sent
            current_chunk_size = min(requested_size, remaining)
            
            # 发送块头（4字节长度信息）
            chunk_header = struct.pack('>I', current_chunk_size)
            if self.verbose:
                print(f"Sending chunk header: {current_chunk_size} bytes")
            self.ser.write(chunk_header)
            self.ser.flush()
            
            # 发送数据块
            chunk = file_data[total_sent:total_sent + current_chunk_size]
            if self.verbose:
                print(f"Sending chunk {chunk_count}: {len(chunk)} bytes")
            self.ser.write(chunk)
            self.ser.flush()
            total_sent += len(chunk)
            
            # 等待块接收确认（与传统模式相同）
            if not self.wait_for_message('CHUNK_RECEIVED', 30):
                print("Chunk not acknowledged")
                return False
            
            # 处理响应（与传统模式相同）
            chunk_success = False
            start_time = time.time()
            received_b64_data = None
            
            while time.time() - start_time < 60 and not chunk_success:
                if self.ser.in_waiting > 0:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    if self.verbose:
                        print(f"MCU: {line}")
                    
                    if line.startswith('B64:'):
                        b64_data = line[4:]
                        if len(b64_data) > 10:
                            decoded = self.safe_base64_decode(b64_data)
                            if decoded:
                                received_b64_data = decoded
                                encrypted_data += decoded
                                self.total_processed += len(decoded)
                                if self.verbose:
                                    print(f"✓ Received encrypted chunk {chunk_count}: {len(decoded)} bytes")
                                else:
                                    # 非详细模式下只显示简略信息
                                    print(f"✓ Chunk {chunk_count}: {len(decoded)} bytes")
                            else:
                                if self.verbose:
                                    print(f"Base64 decode failed for chunk {chunk_count}")
                    
                    elif 'CHUNK_PROCESSED' in line:
                        if received_b64_data is not None:
                            if self.verbose:
                                print(f"✓ Chunk {chunk_count} processed successfully")
                            chunk_success = True
                        else:
                            if self.verbose:
                                print(f"Warning: Chunk {chunk_count} processed but no data received")
                            chunk_success = True
                    
                    elif 'STREAM_STATS' in line:
                        if self.verbose:
                            print(f"MCU Stream Stats: {line}")
                        # 不打断处理流程，继续等待CHUNK_PROCESSED
                    
                    elif 'ERROR' in line:
                        print(f"MCU error: {line}")
                        return False
                    
                    elif 'STREAM_COMPLETE' in line:
                        if self.verbose:
                            print("✓ Stream completed during chunk processing")
                        return True
                else:
                    time.sleep(0.01)
            
            if not chunk_success:
                if self.verbose:
                    print(f"Chunk {chunk_count} processing timeout")
                # 即使超时也继续尝试，只要收到了数据
                if received_b64_data is not None:
                    if self.verbose:
                        print(f"Continuing despite timeout (data received)")
                    chunk_success = True
                else:
                    return False
            
            if self.show_progress:
                print(f"Stream progress: {total_sent}/{len(file_data)} bytes ({total_sent/len(file_data)*100:.1f}%)")
        
        # 所有数据发送完毕，发送结束标记
        if self.verbose:
            print("Sending end-of-stream marker (0-length chunk)")
        end_header = struct.pack('>I', 0)
        self.ser.write(end_header)
        self.ser.flush()
        
        # 等待流结束确认
        end_msg = self.wait_for_message('END_OF_STREAM', 30)
        if not end_msg and self.verbose:
            print("Did not receive END_OF_STREAM confirmation")
        
        # 等待流完成
        stream_msg = self.wait_for_message('STREAM_COMPLETE', 30)
        if not stream_msg and self.verbose:
            print("Stream completion not received")
        
        # 保存加密结果
        if encrypted_data:
            with open(output_file, 'wb') as f:
                f.write(nonce)
                f.write(encrypted_data)
                
            print(f"✓ Streaming encryption successful: {output_file}")
            if self.verbose:
                print(f"  Nonce: {nonce.hex()}")
                print(f"  Total encrypted data: {len(encrypted_data)} bytes")
                print(f"  Original file size: {len(file_data)} bytes")
                print(f"  Chunks processed: {chunk_count}")
            return True
        else:
            print("✗ Streaming encryption failed: no encrypted data received")
            return False

    def _decrypt_streaming(self, encrypted_data, nonce, output_file, key, aad=b""):
        """流式模式解密 - 修复版本，正确发送加密块大小"""
        total_sent = 0
        chunk_count = 0
        decrypted_data = b''
        
        # 关键：在开始前给MCU一些预热时间
        if self.verbose:
            print("Allowing MCU hardware warmup...")
        time.sleep(0.3)
        
        # 计算加密块大小（与GCM-SIV加密格式匹配）
        # 重要：每个加密块 = 明文块大小 + 16字节标签
        total_encrypted_size = len(encrypted_data)
        remaining = total_encrypted_size
        
        if self.verbose:
            print(f"Total encrypted data: {total_encrypted_size} bytes")
            print(f"Expected chunk size for decryption: {CHUNK_SIZE + 16} bytes (plaintext + tag)")
        
        while remaining > 0:
            chunk_count += 1
            self.current_chunk = chunk_count
            
            # 等待MCU的WAIT_CHUNK消息
            chunk_line = None
            start_time = time.time()
            while time.time() - start_time < 30 and chunk_line is None:
                if self.ser.in_waiting > 0:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    if self.verbose:
                        print(f"MCU: {line}")
                    
                    if line.startswith('WAIT_CHUNK'):
                        chunk_line = line
                        # 解析MCU请求的块大小
                        try:
                            requested_size = int(line.split(':')[1])
                            if self.verbose:
                                print(f"MCU requested chunk size: {requested_size} bytes")
                        except:
                            requested_size = CHUNK_SIZE + 16  # 默认加密块大小
                    elif 'ERROR' in line:
                        print(f"MCU error: {line}")
                        return False
                    elif 'STREAM_COMPLETE' in line:
                        if self.verbose:
                            print("✓ Stream completed unexpectedly")
                        return True
                time.sleep(0.01)
            
            if chunk_line is None:
                print("No chunk request received")
                return False
            
            # 计算要发送的加密块大小
            # 对于解密模式，每个加密块应该是 (CHUNK_SIZE + 16) 字节
            # 最后一个块可能小于这个值
            expected_chunk_size = CHUNK_SIZE + 16
            chunk_size = min(expected_chunk_size, remaining)
            
            # 检查MCU请求的大小是否与我们的预期匹配
            try:
                requested_size = int(chunk_line.split(':')[1])
                if requested_size != expected_chunk_size and requested_size != chunk_size:
                    if self.verbose:
                        print(f"Warning: MCU requested {requested_size} bytes, but we expected {expected_chunk_size}")
                    # 使用MCU请求的大小，但不能超过剩余数据
                    chunk_size = min(requested_size, remaining)
            except:
                pass  # 使用我们计算的chunk_size
            
            # 发送块头（4字节长度信息）
            chunk_header = struct.pack('>I', chunk_size)
            if self.verbose:
                print(f"Sending encrypted chunk header: {chunk_size} bytes")
            self.ser.write(chunk_header)
            self.ser.flush()
            
            # 发送加密数据块
            chunk = encrypted_data[total_sent:total_sent + chunk_size]
            if self.verbose:
                print(f"Sending encrypted chunk {chunk_count}: {len(chunk)} bytes")
            self.ser.write(chunk)
            self.ser.flush()
            total_sent += len(chunk)
            remaining -= len(chunk)
            
            # 等待块接收确认
            ack_msg = self.wait_for_message('CHUNK_RECEIVED', 30)
            if not ack_msg:
                print("Chunk not acknowledged")
                return False
            
            # 处理响应
            chunk_success = False
            start_time = time.time()
            received_b64_data = None
            
            while time.time() - start_time < 30 and not chunk_success:  # 缩短超时时间
                if self.ser.in_waiting > 0:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    if self.verbose:
                        print(f"MCU: {line}")
                    
                    if line.startswith('B64:'):
                        b64_data = line[4:]
                        decoded = self.safe_base64_decode(b64_data)
                        if decoded:
                            received_b64_data = decoded
                            decrypted_data += decoded
                            self.total_processed += len(decoded)
                            if self.verbose:
                                print(f"✓ Received decrypted chunk {chunk_count}: {len(decoded)} bytes")
                            else:
                                # 非详细模式下只显示简略信息
                                print(f"✓ Chunk {chunk_count}: {len(decoded)} bytes")
                        else:
                            if self.verbose:
                                print(f"Base64 decode failed for chunk {chunk_count}")
                    
                    elif 'CHUNK_PROCESSED' in line:
                        if received_b64_data is not None:
                            if self.verbose:
                                print(f"✓ Chunk {chunk_count} processed successfully")
                            chunk_success = True
                        else:
                            if self.verbose:
                                print(f"Warning: Chunk {chunk_count} processed but no data received")
                            chunk_success = True
                    
                    elif 'STREAM_STATS' in line:
                        if self.verbose:
                            print(f"MCU Stream Stats: {line}")
                        # 不打断处理流程，继续等待CHUNK_PROCESSED
                    
                    elif 'ERROR' in line:
                        print(f"MCU error: {line}")
                        return False
                    
                    elif 'STREAM_COMPLETE' in line:
                        if self.verbose:
                            print("✓ Stream completed during chunk processing")
                        return True
                else:
                    time.sleep(0.01)
            
            if not chunk_success:
                # 即使没有收到CHUNK_PROCESSED，如果收到了数据就继续
                if received_b64_data is not None:
                    if self.verbose:
                        print(f"⚠ Chunk {chunk_count} completed without confirmation (data received)")
                    chunk_success = True
                else:
                    print(f"✗ Chunk {chunk_count} failed: no data received")
                    return False
            
            if self.show_progress:
                print(f"Stream progress: {total_sent}/{total_encrypted_size} bytes ({total_sent/total_encrypted_size*100:.1f}%)")
        
        # 所有数据发送完毕，发送结束标记
        if self.verbose:
            print("Sending end-of-stream marker (0-length chunk)")
        end_header = struct.pack('>I', 0)
        self.ser.write(end_header)
        self.ser.flush()
        
        # 等待流结束确认
        end_msg = self.wait_for_message('END_OF_STREAM', 30)
        if not end_msg and self.verbose:
            print("Did not receive END_OF_STREAM confirmation")
        
        # 等待流完成
        stream_msg = self.wait_for_message('STREAM_COMPLETE', 30)
        if not stream_msg and self.verbose:
            print("Stream completion not received")
        
        # 保存解密结果
        if decrypted_data:
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
                
            print(f"✓ Streaming decryption successful: {output_file}")
            if self.verbose:
                print(f"  Plaintext: {len(decrypted_data)} bytes")
                print(f"  Total encrypted data processed: {total_sent}/{total_encrypted_size} bytes")
                print(f"  Chunks processed: {chunk_count}")
                
                # 验证解密结果
                expected_plaintext_size = total_encrypted_size - (chunk_count * 16)
                if len(decrypted_data) == expected_plaintext_size:
                    print(f"  ✓ Decrypted size matches expected: {len(decrypted_data)} bytes")
                else:
                    print(f"  ⚠ Decrypted size mismatch: expected {expected_plaintext_size}, got {len(decrypted_data)}")
            
            return True
        else:
            print("✗ Streaming decryption failed: no decrypted data received")
            return False
        
    def decrypt_file(self, input_file, output_file, custom_key=None, custom_aad=b""):
        """解密文件（仅支持流式模式）"""
        if not self.connect():
            return False
            
        try:
            # 读取加密文件（格式: nonce + 所有加密块）
            with open(input_file, 'rb') as f:
                nonce = f.read(16)  # 基础Nonce
                encrypted_data = f.read()  # 所有加密块
                
            print(f"Encrypted file: {len(encrypted_data)} bytes encrypted data")
            if self.verbose:
                print(f"Nonce from file: {nonce.hex().upper()}")
            
            # 确定密钥
            if custom_key is None:
                key = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
                print(f"使用默认密钥: {key.hex().upper()}")
            else:
                key = custom_key
                print(f"使用自定义密钥: {key.hex().upper()}")
            
            # 确定AAD
            aad = custom_aad
            if len(aad) > 0:
                print(f"使用AAD: {aad.hex().upper()} (长度: {len(aad)}字节)")
            else:
                print("未使用AAD")
            
            # 初始化进度变量
            self.total_size = len(encrypted_data)
            self.total_processed = 0
            self.current_chunk = 0
            
            # 验证文件完整性
            if len(encrypted_data) == 0:
                print("Error: Encrypted data is empty")
                return False
                
            print(f"Starting decryption process (streaming mode)...")
            
            # 等待MCU准备
            if not self.wait_for_message('READY', 15):
                print("MCU not ready")
                return False
                
            # 进入流模式
            if not self.send_and_wait(b'n', 'NEW_STREAM_MODE'):
                return False
                
            # 等待操作选择
            if not self.wait_for_message('WAIT_OPERATION'):
                return False
                
            # 发送解密操作
            if not self.send_and_wait(b'd', 'ACK'):
                return False
                
            # 等待密钥请求
            if not self.wait_for_message('WAIT_KEY'):
                return False
                
            # 发送密钥
            if not self.send_and_wait(key, 'ACK'):
                return False
                
            # 等待Nonce请求  
            if not self.wait_for_message('WAIT_NONCE'):
                return False
                
            # 发送Nonce
            if not self.send_and_wait(nonce, 'ACK'):
                return False
                
            # 发送AAD长度
            print("WAIT_AAD_LEN")
            aad_len = len(aad)
            aad_len_data = struct.pack('>I', aad_len)
            if not self.send_and_wait(aad_len_data, 'ACK'):
                print("注意: MCU可能不支持AAD，继续处理...")
                # 即使不支持AAD也继续，MCU会忽略AAD
                
            # 发送AAD数据（如果有）
            if aad_len > 0:
                print("WAIT_AAD_DATA")
                if not self.send_and_wait(aad, 'ACK'):
                    print("注意: AAD发送失败，继续处理...")
                
            print("✓ Entered streaming mode")
            
            # 流式模式发送数据
            return self._decrypt_streaming(encrypted_data, nonce, output_file, key, aad)
                
        except Exception as e:
            print(f"Decryption error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.disconnect()
    
    def verify_encrypted_file(self, input_file):
        """验证加密文件的完整性"""
        try:
            with open(input_file, 'rb') as f:
                nonce = f.read(16)
                encrypted_data = f.read()
                
            print(f"Encrypted file verification:")
            print(f"  Nonce: {len(nonce)} bytes")
            print(f"  Encrypted data: {len(encrypted_data)} bytes")
            
            # 检查基本完整性
            if len(nonce) != 16:
                print("  ✗ Invalid nonce size")
                return False
                
            if len(encrypted_data) == 0:
                print("  ✗ No encrypted data")
                return False
                
            print("  ✓ File structure appears valid")
            return True
            
        except Exception as e:
            print(f"  ✗ Verification error: {e}")
            return False

def verify_files(file1, file2):
    """验证两个文件是否相同"""
    try:
        with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
            content1 = f1.read()
            content2 = f2.read()
            
            if content1 == content2:
                print("✓ SUCCESS: Files are identical")
                print(f"  {file1}: {len(content1)} bytes")
                print(f"  {file2}: {len(content2)} bytes")
                return True
            else:
                print("✗ FAILED: Files differ")
                print(f"  {file1}: {len(content1)} bytes")
                print(f"  {file2}: {len(content2)} bytes")
                
                # 找出差异
                min_len = min(len(content1), len(content2))
                differences = 0
                for i in range(min_len):
                    if content1[i] != content2[i]:
                        differences += 1
                        if differences == 1:
                            print(f"  First difference at byte {i}: 0x{content1[i]:02x} vs 0x{content2[i]:02x}")
                
                if differences > 0:
                    print(f"  Total differences: {differences}")
                    
                return False
    except Exception as e:
        print(f"Error comparing files: {e}")
        return False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="GCM-SIV File Encryption/Decryption System (Streaming Mode Only)")
    parser.add_argument("--port", default="COM3", help="Serial port (default: COM3)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-progress", action="store_true", help="Disable progress display")
    
    args = parser.parse_args()
    
    port = args.port
    verbose = args.verbose
    show_progress = not args.no_progress
    
    print("GCM-SIV File Encryption/Decryption System (Streaming Mode Only)")
    print("1. Encrypt file (streaming mode)")
    print("2. Decrypt file (streaming mode)") 
    print("3. Encrypt -> Decrypt -> Compare (streaming mode)")
    print("4. Verify files")
    
    choice = input("Choose operation (1-4): ").strip()
    
    processor = GCM_SIV_FileProcessor(port, verbose=verbose, show_progress=show_progress)
    
    if choice == "1":
        input_file = input("Input file [input.txt]: ").strip() or default_input
        output_file = input("Output file [encrypted.bin]: ").strip() or default_ciphertext
        
        if not os.path.exists(input_file):
            print(f"Input file does not exist: {input_file}")
            return
        
        # 获取用户输入
        key = get_user_key()
        nonce = get_user_nonce()
        aad = get_user_aad()
        
        # 流式模式加密
        success = processor.encrypt_file(input_file, output_file, 
                                         custom_key=key, 
                                         custom_nonce=nonce, 
                                         custom_aad=aad)
        if success and os.path.exists(output_file):
            processor.verify_encrypted_file(output_file)
        
    elif choice == "2":
        input_file = input("Input file [encrypted.bin]: ").strip() or default_ciphertext
        output_file = input("Output file [decrypted.txt]: ").strip() or default_output
        
        if not os.path.exists(input_file):
            print(f"Input file does not exist: {input_file}")
            return
        
        # 获取用户输入
        key = get_user_key()
        aad = get_user_aad()
        
        # 流式模式解密
        processor.decrypt_file(input_file, output_file, 
                               custom_key=key, 
                               custom_aad=aad)
        
    elif choice == "3":
        # 连续测试：加密 -> 解密 -> 验证
        print("=== Continuous Test: Encrypt -> Decrypt -> Compare ===")
        
        if not os.path.exists(default_input):
            print("Please create input.txt file first")
            return
            
        # 加密（流式模式）- 使用默认值
        print("\n--- Step 1: Encryption (使用默认值) ---")
        encryption_success = processor.encrypt_file(default_input, default_ciphertext)
        
        # 检查加密结果
        if encryption_success:
            if os.path.exists(default_ciphertext):
                print(f"✓ Encryption file created: {default_ciphertext}")
                file_size = os.path.getsize(default_ciphertext)
                print(f"  File size: {file_size} bytes")
                
                print("\n--- Step 2: Decryption (使用默认值) ---")
                if processor.decrypt_file(default_ciphertext, default_output):
                    print("\n--- Step 3: Verification ---")
                    verify_files(default_input, default_output)
                else:
                    print("✗ Decryption failed")
            else:
                print(f"✗ Encrypted file not found: {default_ciphertext}")
        else:
            print("✗ Encryption failed")

    elif choice == "4":
        verify_files(default_input, default_output)

    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()