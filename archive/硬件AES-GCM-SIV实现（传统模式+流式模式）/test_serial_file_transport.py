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
STREAMING_MODE_MARKER = 0xFFFFFFFF  # 流式模式标记

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
        self.use_streaming_mode = False  # 是否使用流式模式
        self.max_file_size = 100 * 1024 * 1024  # 100MB限制
        
    def set_streaming_mode(self, enable=True):
        """设置是否使用流式模式"""
        self.use_streaming_mode = enable
        if enable:
            print("Using streaming mode (no file size limit)")
        else:
            print(f"Using traditional mode (max {self.max_file_size/1024/1024:.0f}MB)")
    
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
            print(f"Connected to {self.port}")
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False
            
    def disconnect(self):
        """断开连接"""
        if self.ser and self.ser.is_open:
            self.ser.close()
            print("Disconnected")
            
    def read_mcu_output(self, timeout=10):
        """读取MCU输出并显示"""
        start_time = time.time()
        output_lines = []
        while time.time() - start_time < timeout:
            if self.ser.in_waiting > 0:
                line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                if line:
                    print(f"MCU: {line}")
                    output_lines.append(line)
            else:
                time.sleep(0.01)
        return output_lines
        
    def wait_for_message(self, expected_msg, timeout=10):
        """等待特定消息 - 增强版本"""
        print(f"Waiting for: {expected_msg}")
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.ser.in_waiting > 0:
                line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                print(f"MCU: {line}")
                if expected_msg in line:
                    return line
                if 'ERROR' in line:
                    print(f"MCU error: {line}")
                    return None
                if 'STREAM_COMPLETE' in line:
                    print("✓ Stream completed while waiting for other message")
                    return 'STREAM_COMPLETE'
                if 'STREAM_ABORTED' in line:
                    print("✗ Stream aborted")
                    return 'STREAM_ABORTED'
                if 'END_OF_STREAM_RECEIVED' in line:
                    print("✓ End of stream received")
                    return 'END_OF_STREAM_RECEIVED'
            time.sleep(0.01)
        print(f"Timeout waiting for: {expected_msg}")
        return None
        
    def send_and_wait(self, data, expected_response, timeout=10):
        """发送数据并等待响应"""
        if isinstance(data, str):
            data = data.encode()
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
                print(f"Invalid Base64 length: {len(b64_data)}")
                return None
                
            # 尝试解码
            decoded = base64.b64decode(b64_data)
            return decoded
        except Exception as e:
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
            print("Sending end-of-stream marker (0-length chunk)")
            self.ser.write(chunk_header)
            self.ser.flush()
            return True
        else:
            chunk_header = struct.pack('>I', len(chunk_data))
            print(f"Sending chunk header: {len(chunk_data)} bytes")
            self.ser.write(chunk_header)
            self.ser.flush()
            
            # 等待MCU的WAIT_STREAM_CHUNK响应
            wait_msg = self.wait_for_message('WAIT_STREAM_CHUNK', 10)
            if not wait_msg:
                print("Did not receive WAIT_STREAM_CHUNK")
                return False
                
            # 发送实际数据
            print(f"Sending chunk data: {len(chunk_data)} bytes")
            self.ser.write(chunk_data)
            self.ser.flush()
            return True
    
    def encrypt_file(self, input_file, output_file, use_streaming=None):
        """加密文件（支持流式模式）"""
        if use_streaming is not None:
            self.set_streaming_mode(use_streaming)
            
        if not self.connect():
            return False
            
        try:
            # 读取输入文件
            with open(input_file, 'rb') as f:
                file_data = f.read()
                
            print(f"File size: {len(file_data)} bytes")
            
            # 检查是否需要使用流式模式
            file_too_large = len(file_data) > self.max_file_size
            
            if file_too_large and not self.use_streaming_mode:
                print(f"Warning: File size ({len(file_data)} bytes) exceeds limit ({self.max_file_size} bytes)")
                print("Automatically switching to streaming mode")
                self.set_streaming_mode(True)
            
            # 初始化进度变量
            self.total_size = len(file_data)
            self.total_processed = 0
            self.current_chunk = 0
            self.total_chunks = (len(file_data) + CHUNK_SIZE - 1) // CHUNK_SIZE
            
            # 生成随机nonce
            nonce = secrets.token_bytes(16)
            # 使用默认密钥
            key = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
            
            print(f"Starting encryption process ({'streaming' if self.use_streaming_mode else 'traditional'} mode)...")
            
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
                
            # 等待文件大小请求
            if not self.wait_for_message('WAIT_SIZE'):
                return False
                
            # 发送文件大小或流式模式标记
            if self.use_streaming_mode:
                size_data = struct.pack('>I', STREAMING_MODE_MARKER)
                if not self.send_and_wait(size_data, 'STREAMING_MODE'):
                    return False
                    
                # 等待ACK
                if not self.wait_for_message('ACK'):
                    return False
                    
                # 等待数据就绪（流式模式）
                if not self.wait_for_message('READY_FOR_DATA'):
                    return False
                    
                print("✓ Entered streaming mode")
                
                # 流式模式发送数据
                return self._encrypt_streaming(file_data, nonce, output_file)
            else:
                # 传统模式
                size_data = struct.pack('>I', len(file_data))
                if not self.send_and_wait(size_data, 'ACK'):
                    return False
                    
                # 等待数据就绪
                if not self.wait_for_message('READY_FOR_DATA'):
                    return False
                    
                print("✓ Entered traditional mode")
                
                # 传统模式发送数据
                return self._encrypt_traditional(file_data, nonce, output_file)
                
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
                    print(f"MCU: {line}")
                    
                    if line.startswith('WAIT_CHUNK'):
                        chunk_line = line
                    elif 'ERROR' in line:
                        print(f"MCU error: {line}")
                        return False
                    elif 'STREAM_COMPLETE' in line:
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
            print(f"Sending chunk header: {current_chunk_size} bytes")
            self.ser.write(chunk_header)
            self.ser.flush()
            
            # 发送数据块
            chunk = file_data[total_sent:total_sent + current_chunk_size]
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
                    print(f"MCU: {line}")
                    
                    if line.startswith('B64:'):
                        b64_data = line[4:]
                        if len(b64_data) > 10:
                            decoded = self.safe_base64_decode(b64_data)
                            if decoded:
                                received_b64_data = decoded
                                encrypted_data += decoded
                                self.total_processed += len(decoded)
                                print(f"✓ Received encrypted chunk {chunk_count}: {len(decoded)} bytes")
                            else:
                                print(f"Base64 decode failed for chunk {chunk_count}")
                    
                    elif 'CHUNK_PROCESSED' in line:
                        if received_b64_data is not None:
                            print(f"✓ Chunk {chunk_count} processed successfully")
                            chunk_success = True
                        else:
                            print(f"Warning: Chunk {chunk_count} processed but no data received")
                            chunk_success = True
                    
                    elif 'STREAM_STATS' in line:
                        print(f"MCU Stream Stats: {line}")
                        # 不打断处理流程，继续等待CHUNK_PROCESSED
                    
                    elif 'ERROR' in line:
                        print(f"MCU error: {line}")
                        return False
                    
                    elif 'STREAM_COMPLETE' in line:
                        print("✓ Stream completed during chunk processing")
                        return True
                else:
                    time.sleep(0.01)
            
            if not chunk_success:
                print(f"Chunk {chunk_count} processing timeout")
                # 即使超时也继续尝试，只要收到了数据
                if received_b64_data is not None:
                    print(f"Continuing despite timeout (data received)")
                    chunk_success = True
                else:
                    return False
            
            print(f"Stream progress: {total_sent}/{len(file_data)} bytes")
        
        # 所有数据发送完毕，发送结束标记
        print("Sending end-of-stream marker (0-length chunk)")
        end_header = struct.pack('>I', 0)
        self.ser.write(end_header)
        self.ser.flush()
        
        # 等待流结束确认
        end_msg = self.wait_for_message('END_OF_STREAM', 30)
        if not end_msg:
            print("Did not receive END_OF_STREAM confirmation")
        
        # 等待流完成
        stream_msg = self.wait_for_message('STREAM_COMPLETE', 30)
        if not stream_msg:
            print("Stream completion not received")
        
        # 保存加密结果
        if encrypted_data:
            with open(output_file, 'wb') as f:
                f.write(nonce)
                f.write(encrypted_data)
                
            print(f"✓ Streaming encryption successful: {output_file}")
            print(f"  Nonce: {nonce.hex()}")
            print(f"  Total encrypted data: {len(encrypted_data)} bytes")
            print(f"  Original file size: {len(file_data)} bytes")
            print(f"  Chunks processed: {chunk_count}")
            return True
        else:
            print("✗ Streaming encryption failed: no encrypted data received")
            return False

    def _decrypt_streaming(self, encrypted_data, nonce, output_file):
        """流式模式解密 - 修复版本，正确发送加密块大小"""
        total_sent = 0
        chunk_count = 0
        decrypted_data = b''
        
        # 关键：在开始前给MCU一些预热时间
        print("Allowing MCU hardware warmup...")
        time.sleep(0.3)
        
        # 计算加密块大小（与GCM-SIV加密格式匹配）
        # 重要：每个加密块 = 明文块大小 + 16字节标签
        total_encrypted_size = len(encrypted_data)
        remaining = total_encrypted_size
        
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
                    print(f"MCU: {line}")
                    
                    if line.startswith('WAIT_CHUNK'):
                        chunk_line = line
                        # 解析MCU请求的块大小
                        try:
                            requested_size = int(line.split(':')[1])
                            print(f"MCU requested chunk size: {requested_size} bytes")
                        except:
                            requested_size = CHUNK_SIZE + 16  # 默认加密块大小
                    elif 'ERROR' in line:
                        print(f"MCU error: {line}")
                        return False
                    elif 'STREAM_COMPLETE' in line:
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
                    print(f"Warning: MCU requested {requested_size} bytes, but we expected {expected_chunk_size}")
                    # 使用MCU请求的大小，但不能超过剩余数据
                    chunk_size = min(requested_size, remaining)
            except:
                pass  # 使用我们计算的chunk_size
            
            # 发送块头（4字节长度信息）
            chunk_header = struct.pack('>I', chunk_size)
            print(f"Sending encrypted chunk header: {chunk_size} bytes")
            self.ser.write(chunk_header)
            self.ser.flush()
            
            # 发送加密数据块
            chunk = encrypted_data[total_sent:total_sent + chunk_size]
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
                    print(f"MCU: {line}")
                    
                    if line.startswith('B64:'):
                        b64_data = line[4:]
                        decoded = self.safe_base64_decode(b64_data)
                        if decoded:
                            received_b64_data = decoded
                            decrypted_data += decoded
                            self.total_processed += len(decoded)
                            print(f"✓ Received decrypted chunk {chunk_count}: {len(decoded)} bytes")
                        else:
                            print(f"Base64 decode failed for chunk {chunk_count}")
                    
                    elif 'CHUNK_PROCESSED' in line:
                        if received_b64_data is not None:
                            print(f"✓ Chunk {chunk_count} processed successfully")
                            chunk_success = True
                        else:
                            print(f"Warning: Chunk {chunk_count} processed but no data received")
                            chunk_success = True
                    
                    elif 'STREAM_STATS' in line:
                        print(f"MCU Stream Stats: {line}")
                        # 不打断处理流程，继续等待CHUNK_PROCESSED
                    
                    elif 'ERROR' in line:
                        print(f"MCU error: {line}")
                        return False
                    
                    elif 'STREAM_COMPLETE' in line:
                        print("✓ Stream completed during chunk processing")
                        return True
                else:
                    time.sleep(0.01)
            
            if not chunk_success:
                # 即使没有收到CHUNK_PROCESSED，如果收到了数据就继续
                if received_b64_data is not None:
                    print(f"⚠ Chunk {chunk_count} completed without confirmation (data received)")
                    chunk_success = True
                else:
                    print(f"✗ Chunk {chunk_count} failed: no data received")
                    return False
            
            print(f"Stream progress: {total_sent}/{total_encrypted_size} bytes ({total_sent/total_encrypted_size*100:.1f}%)")
        
        # 所有数据发送完毕，发送结束标记
        print("Sending end-of-stream marker (0-length chunk)")
        end_header = struct.pack('>I', 0)
        self.ser.write(end_header)
        self.ser.flush()
        
        # 等待流结束确认
        end_msg = self.wait_for_message('END_OF_STREAM', 30)
        if not end_msg:
            print("Did not receive END_OF_STREAM confirmation")
        
        # 等待流完成
        stream_msg = self.wait_for_message('STREAM_COMPLETE', 30)
        if not stream_msg:
            print("Stream completion not received")
        
        # 保存解密结果
        if decrypted_data:
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
                
            print(f"✓ Streaming decryption successful: {output_file}")
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
        
    def _encrypt_traditional(self, file_data, nonce, output_file):
        """传统模式加密"""
        total_sent = 0
        chunk_count = 0
        encrypted_data = b''
        stream_completed = False
        
        while total_sent < len(file_data) and not stream_completed:
            chunk_count += 1
            self.current_chunk = chunk_count
            
            # 等待块请求
            chunk_line = None
            start_time = time.time()
            while time.time() - start_time < 30 and chunk_line is None and not stream_completed:
                if self.ser.in_waiting > 0:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    print(f"MCU: {line}")
                    
                    if line.startswith('WAIT_CHUNK'):
                        chunk_line = line
                    elif 'STREAM_COMPLETE' in line:
                        print("✓ Stream completed - all data processed")
                        stream_completed = True
                        break
                    elif 'ERROR' in line:
                        print(f"MCU error: {line}")
                        return False
                time.sleep(0.01)
            
            if stream_completed:
                break
                
            if chunk_line is None:
                print("No chunk request received")
                return False
                
            # 解析请求的块大小
            try:
                requested_size = int(chunk_line.split(':')[1])
            except:
                requested_size = CHUNK_SIZE
                
            remaining = len(file_data) - total_sent
            current_chunk_size = min(requested_size, remaining)
            
            # 发送数据块
            chunk = file_data[total_sent:total_sent + current_chunk_size]
            print(f"Sending chunk {chunk_count}: {len(chunk)} bytes")
            self.ser.write(chunk)
            self.ser.flush()
            total_sent += len(chunk)
            
            # 等待块接收确认
            if not self.wait_for_message('CHUNK_RECEIVED', 30):
                print("Chunk not acknowledged")
                return False
            
            # 处理响应
            chunk_success = False
            start_time = time.time()
            received_b64_data = None
            
            while time.time() - start_time < 60 and not chunk_success and not stream_completed:
                if self.ser.in_waiting > 0:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    print(f"MCU: {line}")
                    
                    if line.startswith('B64:'):
                        b64_data = line[4:]
                        if len(b64_data) > 10:
                            decoded = self.safe_base64_decode(b64_data)
                            if decoded:
                                received_b64_data = decoded
                                encrypted_data += decoded
                                self.total_processed += len(decoded)
                                if not self.verbose:
                                    self._update_progress()
                            else:
                                print(f"Base64 decode failed for chunk {chunk_count}")
                    
                    elif 'CHUNK_PROCESSED' in line:
                        if received_b64_data is not None:
                            print(f"Chunk {chunk_count} processed successfully")
                            chunk_success = True
                        else:
                            print(f"Warning: Chunk {chunk_count} processed but no data received")
                            chunk_success = True
                    
                    elif 'STREAM_COMPLETE' in line:
                        print("✓ Stream completed during chunk processing")
                        stream_completed = True
                        chunk_success = True
                        break
                        
                    elif 'ERROR' in line:
                        print(f"MCU error: {line}")
                        return False
                
                time.sleep(0.01)
            
            if not chunk_success and not stream_completed:
                print(f"Chunk {chunk_count} processing timeout")
                return False
            
            progress = (total_sent / len(file_data)) * 100
            print(f"Overall progress: {total_sent}/{len(file_data)} bytes ({progress:.1f}%)")
        
        # 保存加密结果
        if encrypted_data:
            with open(output_file, 'wb') as f:
                f.write(nonce)          # 16 bytes 基础Nonce
                f.write(encrypted_data) # 所有加密块
                
            print(f"✓ Encryption successful: {output_file}")
            print(f"  Nonce: {nonce.hex()}")
            print(f"  Total encrypted data: {len(encrypted_data)} bytes")
            print(f"  Original file size: {len(file_data)} bytes")
            return True
        else:
            print("✗ Encryption failed: no encrypted data received")
            return False
    
    def decrypt_file(self, input_file, output_file, use_streaming=None):
        """解密文件（支持流式模式）"""
        if use_streaming is not None:
            self.set_streaming_mode(use_streaming)
            
        if not self.connect():
            return False
            
        try:
            # 读取加密文件（格式: nonce + 所有加密块）
            with open(input_file, 'rb') as f:
                nonce = f.read(16)  # 基础Nonce
                encrypted_data = f.read()  # 所有加密块
                
            print(f"Encrypted file: {len(encrypted_data)} bytes encrypted data")
            print(f"Nonce: {nonce.hex()}")
            
            # 检查是否需要使用流式模式
            file_too_large = len(encrypted_data) > self.max_file_size
            
            if file_too_large and not self.use_streaming_mode:
                print(f"Warning: Encrypted file size ({len(encrypted_data)} bytes) exceeds limit ({self.max_file_size} bytes)")
                print("Automatically switching to streaming mode")
                self.set_streaming_mode(True)
            
            # 初始化进度变量
            self.total_size = len(encrypted_data)
            self.total_processed = 0
            self.current_chunk = 0
            
            # 预先计算加密块大小（仅传统模式需要）
            if not self.use_streaming_mode:
                encrypted_chunk_sizes = self.calculate_encrypted_chunk_sizes(len(encrypted_data))
                self.total_chunks = len(encrypted_chunk_sizes)
            
            # 验证文件完整性
            if len(encrypted_data) == 0:
                print("Error: Encrypted data is empty")
                return False
                
            # 使用默认密钥
            key = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
            
            print(f"Starting decryption process ({'streaming' if self.use_streaming_mode else 'traditional'} mode)...")
            
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
                
            # 等待文件大小请求
            if not self.wait_for_message('WAIT_SIZE'):
                return False
                
            # 发送文件大小或流式模式标记
            if self.use_streaming_mode:
                size_data = struct.pack('>I', STREAMING_MODE_MARKER)
                if not self.send_and_wait(size_data, 'STREAMING_MODE'):
                    return False
                    
                # 等待ACK
                if not self.wait_for_message('ACK'):
                    return False
                    
                # 等待数据就绪（流式模式）
                if not self.wait_for_message('READY_FOR_DATA'):
                    return False
                    
                print("✓ Entered streaming mode")
                
                # 流式模式发送数据
                return self._decrypt_streaming(encrypted_data, nonce, output_file)
            else:
                # 传统模式
                size_data = struct.pack('>I', len(encrypted_data))
                if not self.send_and_wait(size_data, 'ACK'):
                    return False
                    
                # 等待数据就绪
                if not self.wait_for_message('READY_FOR_DATA'):
                    return False
                    
                print("✓ Entered traditional mode")
                
                # 传统模式发送数据
                return self._decrypt_traditional(encrypted_data, nonce, output_file, encrypted_chunk_sizes)
                
        except Exception as e:
            print(f"Decryption error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.disconnect()
    
    def _decrypt_traditional(self, encrypted_data, nonce, output_file, encrypted_chunk_sizes):
        """传统模式解密"""
        total_sent = 0
        chunk_count = 0
        decrypted_data = b''
        stream_completed = False
        
        while total_sent < len(encrypted_data) and not stream_completed:
            chunk_count += 1
            self.current_chunk = chunk_count
            
            # 等待块请求
            chunk_line = None
            start_time = time.time()
            while time.time() - start_time < 30 and chunk_line is None and not stream_completed:
                if self.ser.in_waiting > 0:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    print(f"MCU: {line}")
                    
                    if line.startswith('WAIT_CHUNK'):
                        chunk_line = line
                    elif 'STREAM_COMPLETE' in line:
                        print("✓ Stream completed - all data processed")
                        stream_completed = True
                        break
                    elif 'ERROR' in line:
                        print(f"MCU error: {line}")
                        return False
                time.sleep(0.01)
            
            if stream_completed:
                break
                
            if chunk_line is None:
                print("No chunk request received")
                return False
                
            # 使用预先计算的块大小
            if chunk_count <= len(encrypted_chunk_sizes):
                chunk_size = encrypted_chunk_sizes[chunk_count - 1]
                if self.verbose:
                    print(f"Using pre-calculated chunk size: {chunk_size}")
            else:
                # 如果块数超出预期，使用默认计算
                try:
                    requested_size = int(chunk_line.split(':')[1])
                    chunk_size = min(requested_size, len(encrypted_data) - total_sent)
                except:
                    chunk_size = CHUNK_SIZE + 16
            
            # 发送加密块
            chunk = encrypted_data[total_sent:total_sent + chunk_size]
            print(f"Sending encrypted chunk {chunk_count}: {len(chunk)} bytes")
            self.ser.write(chunk)
            self.ser.flush()
            total_sent += len(chunk)
            
            # 等待块接收确认
            if not self.wait_for_message('CHUNK_RECEIVED', 30):
                print("Chunk not acknowledged")
                return False
            
            # 处理响应
            chunk_processed = False
            start_time = time.time()
            received_b64_data = None
            
            while time.time() - start_time < 60 and not chunk_processed and not stream_completed:
                if self.ser.in_waiting > 0:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    print(f"MCU: {line}")
                    
                    if line.startswith('B64:'):
                        b64_data = line[4:]
                        print(f"Received Base64 data, length: {len(b64_data)}")
                        chunk_decrypted = self.safe_base64_decode(b64_data)
                        if chunk_decrypted:
                            received_b64_data = chunk_decrypted
                            decrypted_data += chunk_decrypted
                            self.total_processed += len(chunk_decrypted)
                            print(f"✓ Successfully decoded chunk {chunk_count}: {len(chunk_decrypted)} bytes")
                        else:
                            print(f"✗ Base64 decode failed for chunk {chunk_count}")
                            
                    elif 'CHUNK_PROCESSED' in line:
                        if received_b64_data is not None:
                            print(f"✓ Chunk {chunk_count} processed successfully with data")
                            chunk_processed = True
                        else:
                            print(f"⚠ Chunk {chunk_count} processed but no Base64 data received")
                            chunk_processed = True
                    
                    elif 'PROGRESS' in line:
                        print(f"MCU Progress: {line}")
                        
                    elif 'ERROR' in line:
                        print(f"MCU error: {line}")
                        return False
                        
                    elif 'STREAM_COMPLETE' in line:
                        print("✓ Stream completed during chunk processing")
                        stream_completed = True
                        chunk_processed = True
                        break
                else:
                    time.sleep(0.01)
            
            if not chunk_processed and not stream_completed:
                print(f"Chunk {chunk_count} processing timeout")
                chunk_processed = True
                
            progress = (total_sent / len(encrypted_data)) * 100
            print(f"Overall progress: {total_sent}/{len(encrypted_data)} bytes ({progress:.1f}%)")
        
        # 等待流完成
        if not stream_completed:
            stream_msg = self.wait_for_message('STREAM_COMPLETE', 30)
            if stream_msg:
                print("✓ Stream completion confirmed")
                stream_completed = True
        
        # 保存解密结果
        if decrypted_data:
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
                
            print(f"✓ Decryption successful: {output_file}")
            print(f"  Plaintext: {len(decrypted_data)} bytes")
            print(f"  Total encrypted data processed: {total_sent}/{len(encrypted_data)} bytes")
            return True
        else:
            print("✗ Decryption failed: no decrypted data received")
            return False
    
    def calculate_encrypted_chunk_sizes(self, total_encrypted_size):
        """计算加密块大小"""
        chunk_sizes = []
        remaining = total_encrypted_size
        
        while remaining > 0:
            if remaining >= (CHUNK_SIZE + 16):
                chunk_sizes.append(CHUNK_SIZE + 16)
                remaining -= (CHUNK_SIZE + 16)
            else:
                # 最后一个块
                chunk_sizes.append(remaining)
                remaining = 0
        
        print(f"Calculated {len(chunk_sizes)} chunks for {total_encrypted_size} bytes")
        return chunk_sizes
    
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
                
            # 检查块结构
            total_size = 0
            chunk_sizes = self.calculate_encrypted_chunk_sizes(len(encrypted_data))
            calculated_total = sum(chunk_sizes)
            
            if calculated_total != len(encrypted_data):
                print(f"  ✗ Size mismatch: calculated {calculated_total}, actual {len(encrypted_data)}")
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
    port = "COM3"  # 修改为您的串口
    
    print("GCM-SIV File Encryption/Decryption System")
    print("1. Encrypt file (auto-select mode)")
    print("2. Decrypt file (auto-select mode)") 
    print("3. Encrypt -> Decrypt -> Compare (auto-select mode)")
    print("4. Encrypt file (traditional mode, up to 100MB)")
    print("5. Encrypt file (streaming mode, no size limit)")
    print("6. Decrypt file (traditional mode)")
    print("7. Decrypt file (streaming mode)")
    print("8. Verify files")
    
    choice = input("Choose operation (1-8): ").strip()
    
    processor = GCM_SIV_FileProcessor(port)
    
    if choice == "1":
        input_file = input("Input file [input.txt]: ").strip() or default_input
        output_file = input("Output file [encrypted.bin]: ").strip() or default_ciphertext
        
        if not os.path.exists(input_file):
            print(f"Input file does not exist: {input_file}")
            return
            
        # 自动选择模式（根据文件大小）
        success = processor.encrypt_file(input_file, output_file)
        if success and os.path.exists(output_file):
            processor.verify_encrypted_file(output_file)
        
    elif choice == "2":
        input_file = input("Input file [encrypted.bin]: ").strip() or default_ciphertext
        output_file = input("Output file [decrypted.txt]: ").strip() or default_output
        
        if not os.path.exists(input_file):
            print(f"Input file does not exist: {input_file}")
            return
            
        # 自动选择模式
        processor.decrypt_file(input_file, output_file)
        
    elif choice == "3":
        # 连续测试：加密 -> 解密 -> 验证
        print("=== Continuous Test: Encrypt -> Decrypt -> Compare ===")
        
        if not os.path.exists(default_input):
            print("Please create input.txt file first")
            return
            
        # 加密（自动选择模式）
        print("\n--- Step 1: Encryption ---")
        encryption_success = processor.encrypt_file(default_input, default_ciphertext)
        
        # 检查加密结果
        if encryption_success:
            if os.path.exists(default_ciphertext):
                print(f"✓ Encryption file created: {default_ciphertext}")
                file_size = os.path.getsize(default_ciphertext)
                print(f"  File size: {file_size} bytes")
                
                print("\n--- Step 2: Decryption ---")
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
        input_file = input("Input file [input.txt]: ").strip() or default_input
        output_file = input("Output file [encrypted.bin]: ").strip() or default_ciphertext
        
        if not os.path.exists(input_file):
            print(f"Input file does not exist: {input_file}")
            return
            
        # 强制使用传统模式
        processor.set_streaming_mode(False)
        success = processor.encrypt_file(input_file, output_file, use_streaming=False)
        
    elif choice == "5":
        input_file = input("Input file [input.txt]: ").strip() or default_input
        output_file = input("Output file [encrypted.bin]: ").strip() or default_ciphertext
        
        if not os.path.exists(input_file):
            print(f"Input file does not exist: {input_file}")
            return
            
        # 强制使用流式模式
        processor.set_streaming_mode(True)
        success = processor.encrypt_file(input_file, output_file, use_streaming=True)
        
    elif choice == "6":
        input_file = input("Input file [encrypted.bin]: ").strip() or default_ciphertext
        output_file = input("Output file [decrypted.txt]: ").strip() or default_output
        
        if not os.path.exists(input_file):
            print(f"Input file does not exist: {input_file}")
            return
            
        # 强制使用传统模式
        processor.set_streaming_mode(False)
        processor.decrypt_file(input_file, output_file, use_streaming=False)
        
    elif choice == "7":
        input_file = input("Input file [encrypted.bin]: ").strip() or default_ciphertext
        output_file = input("Output file [decrypted.txt]: ").strip() or default_output
        
        if not os.path.exists(input_file):
            print(f"Input file does not exist: {input_file}")
            return
            
        # 强制使用流式模式
        processor.set_streaming_mode(True)
        processor.decrypt_file(input_file, output_file, use_streaming=True)

    elif choice == "8":
        verify_files(default_input, default_output)

    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()