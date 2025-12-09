import serial
import time
import os
import base64
import struct
import secrets
import sys
import json
import random
import string
import hashlib
import threading
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
import statistics

# ==================== 使用 test_serial_file_transport.py 中的通信协议 ====================

BaudRate = 115200
CHUNK_SIZE = 1024

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
        self.custom_key = None
        self.custom_nonce = None
        self.custom_aad = b''
        
    def set_custom_parameters(self, key=None, nonce=None, aad=None):
        """设置用户自定义参数"""
        if key is not None:
            if len(key) != 16:
                raise ValueError("Key must be 16 bytes")
            self.custom_key = key
        
        if nonce is not None:
            if len(nonce) != 16:
                raise ValueError("Nonce must be 16 bytes")
            self.custom_nonce = nonce
        
        if aad is not None:
            self.custom_aad = aad if isinstance(aad, bytes) else aad.encode('utf-8')
        
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
                
                # 检查是否为期望的消息
                if expected_msg in line:
                    return line
                
                # 检查错误消息
                if 'ERROR' in line:
                    print(f"MCU error: {line}")
                    return None
                
                # 检查流结束相关消息
                for end_msg in ['STREAM_COMPLETE', 'END_OF_STREAM', 'SUMMARY:']:
                    if end_msg in line:
                        return line
                
                # 如果是其他消息但包含期望的关键字，也返回
                if expected_msg != 'CHUNK_RECEIVED' and expected_msg != 'WAIT_CHUNK':
                    # 检查是否有部分匹配
                    if line.startswith(expected_msg.split(':')[0]):
                        return line
            else:
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
            import re
            b64_data = re.sub(r'[^A-Za-z0-9+/=]', '', b64_data)
            
            padding_needed = (4 - len(b64_data) % 4) % 4
            b64_data += '=' * padding_needed
            
            if len(b64_data) < 4 or len(b64_data) % 4 != 0:
                if self.verbose:
                    print(f"Invalid Base64 length: {len(b64_data)}")
                return None
                
            decoded = base64.b64decode(b64_data)
            return decoded
        except Exception as e:
            if self.verbose:
                print(f"Base64 decode error: {e}")
                print(f"Problematic data length: {len(b64_data)}")
            return None
    
    def send_streaming_chunk(self, chunk_data, is_last=False):
        """在流式模式下发送一个数据块"""
        if not self.ser or not self.ser.is_open:
            print("Serial port not connected")
            return False
            
        if is_last:
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
            
            wait_msg = self.wait_for_message('WAIT_STREAM_CHUNK', 10)
            if not wait_msg:
                if self.verbose:
                    print("Did not receive WAIT_STREAM_CHUNK")
                return False
                
            if self.verbose:
                print(f"Sending chunk data: {len(chunk_data)} bytes")
            self.ser.write(chunk_data)
            self.ser.flush()
            return True
    
    def _encrypt_streaming(self, file_data, nonce, output_file):
        """流式模式加密"""
        total_sent = 0
        chunk_count = 0
        encrypted_data = b''
        
        # 关键：在开始前给MCU一些预热时间
        if self.verbose:
            print("Allowing MCU hardware warmup...")
        time.sleep(0.3)
        
        while total_sent < len(file_data):
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
            
            try:
                requested_size = int(chunk_line.split(':')[1])
            except:
                requested_size = CHUNK_SIZE
            
            remaining = len(file_data) - total_sent
            current_chunk_size = min(requested_size, remaining)
            
            chunk_header = struct.pack('>I', current_chunk_size)
            if self.verbose:
                print(f"Sending chunk header: {current_chunk_size} bytes")
            self.ser.write(chunk_header)
            self.ser.flush()
            
            chunk = file_data[total_sent:total_sent + current_chunk_size]
            if self.verbose:
                print(f"Sending chunk {chunk_count}: {len(chunk)} bytes")
            self.ser.write(chunk)
            self.ser.flush()
            total_sent += len(chunk)
            
            if not self.wait_for_message('CHUNK_RECEIVED', 30):
                print("Chunk not acknowledged")
                return False
            
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
        
        time.sleep(0.1)
        self.ser.write(end_header)
        self.ser.flush()
        
        # 关键：等待MCU处理结束标记
        if self.verbose:
            print("Waiting for MCU to process end-of-stream marker...")
        time.sleep(0.5)
        
        # 等待流结束确认
        end_msg = self.wait_for_message('END_OF_STREAM', 10)
        if not end_msg:
            if self.verbose:
                print("Warning: Did not receive END_OF_STREAM confirmation, but continuing...")
        
        # 等待流完成
        stream_msg = self.wait_for_message('STREAM_COMPLETE', 10)
        if not stream_msg:
            if self.verbose:
                print("Warning: Stream completion not received, but assuming completion...")
        
        # 等待总结信息
        summary_msg = self.wait_for_message('SUMMARY:', 5)
        if summary_msg and self.verbose:
            print(f"MCU Summary: {summary_msg}")
        
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
        
    def encrypt_file(self, input_file, output_file, custom_key=None, custom_nonce=None, custom_aad=b""):
        """加密文件（支持自定义参数）"""
        if not self.connect():
            return False
            
        try:
            with open(input_file, 'rb') as f:
                file_data = f.read()
                
            print(f"File size: {len(file_data)} bytes")
            
            self.total_size = len(file_data)
            self.total_processed = 0
            self.current_chunk = 0
            self.total_chunks = (len(file_data) + CHUNK_SIZE - 1) // CHUNK_SIZE
            
            # 设置自定义参数
            if custom_key is not None:
                self.set_custom_parameters(key=custom_key)
            else:
                self.set_custom_parameters(key=bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]))
            
            if custom_nonce is not None:
                self.set_custom_parameters(nonce=custom_nonce)
                nonce = custom_nonce
            else:
                nonce = secrets.token_bytes(16)
                self.set_custom_parameters(nonce=nonce)
            
            if custom_aad:
                self.set_custom_parameters(aad=custom_aad)
            
            print(f"Encryption parameters:")
            print(f"  Key: {'custom' if custom_key else 'default'}")
            print(f"  Nonce: {'custom' if custom_nonce else 'random'}")
            print(f"  AAD length: {len(custom_aad)} bytes")
            
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
            if not self.send_and_wait(self.custom_key, 'ACK'):
                return False
                
            # 等待Nonce请求  
            if not self.wait_for_message('WAIT_NONCE'):
                return False
                
            # 发送Nonce
            if not self.send_and_wait(nonce, 'ACK'):
                return False
                
            # 等待AAD长度请求
            if not self.wait_for_message('WAIT_AAD_LEN'):
                return False
                
            # 发送AAD长度
            aad_len_data = struct.pack('>I', len(self.custom_aad))
            if not self.send_and_wait(aad_len_data, 'ACK'):
                return False
                
            # 如果AAD长度大于0，发送AAD数据
            if len(self.custom_aad) > 0:
                if not self.wait_for_message('WAIT_AAD'):
                    return False
                
                if not self.send_and_wait(self.custom_aad, 'ACK'):
                    return False
            
            # 等待READY_FOR_DATA
            if not self.wait_for_message('READY_FOR_DATA'):
                return False
                
            print("✓ Entered streaming mode")
            
            return self._encrypt_streaming(file_data, nonce, output_file)
                
        except Exception as e:
            print(f"Encryption error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.disconnect()

    def _decrypt_streaming(self, encrypted_data, nonce, output_file, key, aad=b""):
        """流式模式解密"""
        total_sent = 0
        chunk_count = 0
        decrypted_data = b''
        
        if self.verbose:
            print("Allowing MCU hardware warmup...")
        time.sleep(0.3)
        
        total_encrypted_size = len(encrypted_data)
        remaining = total_encrypted_size
        
        if self.verbose:
            print(f"Total encrypted data: {total_encrypted_size} bytes")
            print(f"Expected chunk size for decryption: {CHUNK_SIZE + 16} bytes (plaintext + tag)")
        
        while remaining > 0:
            chunk_count += 1
            self.current_chunk = chunk_count
            
            chunk_line = None
            start_time = time.time()
            while time.time() - start_time < 30 and chunk_line is None:
                if self.ser.in_waiting > 0:
                    line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                    if self.verbose:
                        print(f"MCU: {line}")
                    
                    if line.startswith('WAIT_CHUNK'):
                        chunk_line = line
                        try:
                            requested_size = int(line.split(':')[1])
                            if self.verbose:
                                print(f"MCU requested chunk size: {requested_size} bytes")
                        except:
                            requested_size = CHUNK_SIZE + 16
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
            
            expected_chunk_size = CHUNK_SIZE + 16
            chunk_size = min(expected_chunk_size, remaining)
            
            try:
                requested_size = int(chunk_line.split(':')[1])
                if requested_size != expected_chunk_size and requested_size != chunk_size:
                    if self.verbose:
                        print(f"Warning: MCU requested {requested_size} bytes, but we expected {expected_chunk_size}")
                    chunk_size = min(requested_size, remaining)
            except:
                pass
            
            chunk_header = struct.pack('>I', chunk_size)
            if self.verbose:
                print(f"Sending encrypted chunk header: {chunk_size} bytes")
            self.ser.write(chunk_header)
            self.ser.flush()
            
            chunk = encrypted_data[total_sent:total_sent + chunk_size]
            if self.verbose:
                print(f"Sending encrypted chunk {chunk_count}: {len(chunk)} bytes")
            self.ser.write(chunk)
            self.ser.flush()
            total_sent += len(chunk)
            remaining -= len(chunk)
            
            ack_msg = self.wait_for_message('CHUNK_RECEIVED', 30)
            if not ack_msg:
                print("Chunk not acknowledged")
                return False
            
            chunk_success = False
            start_time = time.time()
            received_b64_data = None
            
            while time.time() - start_time < 30 and not chunk_success:
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
        
        time.sleep(0.1)
        self.ser.write(end_header)
        self.ser.flush()
        
        # 关键：等待MCU处理结束标记
        if self.verbose:
            print("Waiting for MCU to process end-of-stream marker...")
        time.sleep(0.5)
        
        # 等待流结束确认
        end_msg = self.wait_for_message('END_OF_STREAM', 10)
        if not end_msg:
            if self.verbose:
                print("Warning: Did not receive END_OF_STREAM confirmation, but continuing...")
        
        # 等待流完成
        stream_msg = self.wait_for_message('STREAM_COMPLETE', 10)
        if not stream_msg:
            if self.verbose:
                print("Warning: Stream completion not received, but assuming completion...")
        
        # 等待总结信息
        summary_msg = self.wait_for_message('SUMMARY:', 5)
        if summary_msg and self.verbose:
            print(f"MCU Summary: {summary_msg}")
        
        if decrypted_data:
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
                
            print(f"✓ Streaming decryption successful: {output_file}")
            if self.verbose:
                print(f"  Plaintext: {len(decrypted_data)} bytes")
                print(f"  Total encrypted data processed: {total_sent}/{total_encrypted_size} bytes")
                print(f"  Chunks processed: {chunk_count}")
                
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
        """解密文件（支持自定义参数）"""
        if not self.connect():
            return False
            
        try:
            with open(input_file, 'rb') as f:
                nonce = f.read(16)
                encrypted_data = f.read()
                
            print(f"Encrypted file: {len(encrypted_data)} bytes encrypted data")
            if self.verbose:
                print(f"Nonce from file: {nonce.hex().upper()}")
            
            # 设置自定义参数
            if custom_key is not None:
                self.set_custom_parameters(key=custom_key)
            else:
                self.set_custom_parameters(key=bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]))
            
            if custom_aad:
                self.set_custom_parameters(aad=custom_aad)
            else:
                self.set_custom_parameters(aad=b'')
            
            # 不设置nonce，使用文件中的nonce
            self.custom_nonce = None
            
            print(f"Decryption parameters:")
            print(f"  Key: {'custom' if custom_key else 'default'}")
            print(f"  Nonce: from file")
            print(f"  AAD length: {len(custom_aad)} bytes")
            
            self.total_size = len(encrypted_data)
            self.total_processed = 0
            self.current_chunk = 0
            
            if len(encrypted_data) == 0:
                print("Error: Encrypted data is empty")
                return False
                
            print(f"Starting decryption process (streaming mode)...")
            
            if not self.wait_for_message('READY', 15):
                print("MCU not ready")
                return False
                
            if not self.send_and_wait(b'n', 'NEW_STREAM_MODE'):
                return False
                
            if not self.wait_for_message('WAIT_OPERATION'):
                return False
                
            if not self.send_and_wait(b'd', 'ACK'):
                return False
                
            if not self.wait_for_message('WAIT_KEY'):
                return False
                
            if not self.send_and_wait(self.custom_key, 'ACK'):
                return False
                
            if not self.wait_for_message('WAIT_NONCE'):
                return False
                
            if not self.send_and_wait(nonce, 'ACK'):
                return False
                
            if not self.wait_for_message('WAIT_AAD_LEN'):
                return False
                
            aad_len_data = struct.pack('>I', len(self.custom_aad))
            if not self.send_and_wait(aad_len_data, 'ACK'):
                return False
                
            if len(self.custom_aad) > 0:
                if not self.wait_for_message('WAIT_AAD'):
                    return False
                
                if not self.send_and_wait(self.custom_aad, 'ACK'):
                    return False
            
            if not self.wait_for_message('READY_FOR_DATA'):
                return False
                
            print("✓ Entered streaming mode")
            
            return self._decrypt_streaming(encrypted_data, nonce, output_file, self.custom_key, self.custom_aad)
                
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

# ==================== 跑分测试框架 ====================

class BenchmarkRunner:
    def __init__(self, port: str, project_name: str, output_dir: str = "benchmark_results"):
        self.port = port
        self.project_name = project_name
        self.output_dir = output_dir
        self.results = {
            "project": project_name,
            "timestamp": datetime.now().isoformat(),
            "test_cases": [],
            "summary": {}
        }
        
        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)
        
        # 测试文件定义
        self.small_files = [
            ("256B", 256, 5),      # 5次迭代
            ("1KB", 1024, 5),
            ("4KB", 4096, 5),
            ("16KB", 16384, 5),
            ("64KB", 65536, 5)
        ]
        
        self.medium_files = [
            ("200KB", 200 * 1024, 2),   # 2次迭代
            ("400KB", 400 * 1024, 2),
            ("800KB", 800 * 1024, 2)
        ]
        
        self.large_files = [
            ("1MB", 1024 * 1024, 1),    # 1次迭代
            ("4MB", 4 * 1024 * 1024, 1),
            ("16MB", 16 * 1024 * 1024, 1)
        ]
        
        # 默认key和nonce
        self.default_key = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        self.default_nonce = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        self.default_aad = b""  # 空AAD
        
    def generate_test_file(self, size: int, filename: str) -> str:
        """生成随机测试文件"""
        random.seed(42)  # 固定种子确保可重复
        chars = string.ascii_letters + string.digits + string.punctuation
        
        with open(filename, 'wb') as f:
            remaining = size
            while remaining > 0:
                chunk_size = min(remaining, 1024)
                chunk = ''.join(random.choice(chars) for _ in range(chunk_size)).encode('utf-8')
                f.write(chunk[:chunk_size])
                remaining -= chunk_size
        
        actual_size = os.path.getsize(filename)
        if actual_size != size:
            print(f"Warning: Generated file size mismatch: expected {size}, got {actual_size}")
        
        return filename
    
    def verify_files_identical(self, file1: str, file2: str) -> bool:
        """验证两个文件是否相同"""
        try:
            with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
                content1 = f1.read()
                content2 = f2.read()
                
                if content1 == content2:
                    return True
                else:
                    min_len = min(len(content1), len(content2))
                    differences = sum(1 for i in range(min_len) if content1[i] != content2[i])
                    print(f"  ✗ Files differ: {differences} differences")
                    return False
        except Exception as e:
            print(f"  ✗ Error comparing files: {e}")
            return False
    
    def calculate_hash(self, filename: str) -> str:
        """计算文件哈希值"""
        with open(filename, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    def run_single_iteration(self, file_size: int, iteration: int, 
                           is_warmup: bool = False) -> Dict[str, Any]:
        """运行单次迭代：加密->解密->验证"""
        result = {
            "iteration": iteration,
            "is_warmup": is_warmup,
            "file_size": file_size,
            "success": False,
            "encryption_time": 0,
            "decryption_time": 0,
            "total_time": 0,
            "encryption_throughput": 0,  # B/s
            "decryption_throughput": 0,  # B/s
            "total_throughput": 0,       # B/s
            "error": None,
            "attempts": 1
        }
        
        try:
            # 生成唯一文件名
            base_name = f"test_{file_size}_{iteration}_{'warmup' if is_warmup else 'main'}"
            input_file = os.path.join(self.output_dir, f"{base_name}_input.bin")
            encrypted_file = os.path.join(self.output_dir, f"{base_name}_encrypted.bin")
            decrypted_file = os.path.join(self.output_dir, f"{base_name}_decrypted.bin")
            
            # 生成测试文件
            print(f"  Generating {file_size} bytes test file...")
            self.generate_test_file(file_size, input_file)
            
            # 记录原始文件哈希
            original_hash = self.calculate_hash(input_file)
            
            # 创建处理器实例
            processor = GCM_SIV_FileProcessor(self.port, verbose=False, show_progress=False)
            
            # 加密测试
            print(f"  Encrypting...")
            encrypt_start = time.time()
            encrypt_success = processor.encrypt_file(
                input_file, encrypted_file,
                custom_key=self.default_key,
                custom_nonce=self.default_nonce,
                custom_aad=self.default_aad
            )
            encrypt_end = time.time()
            
            if not encrypt_success:
                result["error"] = "Encryption failed"
                return result
            
            # 验证加密文件
            if not processor.verify_encrypted_file(encrypted_file):
                result["error"] = "Encrypted file verification failed"
                return result
            
            # 解密测试
            print(f"  Decrypting...")
            decrypt_start = time.time()
            decrypt_success = processor.decrypt_file(
                encrypted_file, decrypted_file,
                custom_key=self.default_key,
                custom_aad=self.default_aad
            )
            decrypt_end = time.time()
            
            if not decrypt_success:
                result["error"] = "Decryption failed"
                return result
            
            # 验证解密结果
            print(f"  Verifying...")
            verification_success = self.verify_files_identical(input_file, decrypted_file)
            
            if not verification_success:
                result["error"] = "Verification failed"
                return result
            
            # 计算时间
            encryption_time = encrypt_end - encrypt_start
            decryption_time = decrypt_end - decrypt_start
            total_time = encryption_time + decryption_time
            
            # 计算吞吐量（字节/秒）
            encryption_throughput = file_size / encryption_time if encryption_time > 0 else 0
            decryption_throughput = file_size / decryption_time if decryption_time > 0 else 0
            total_throughput = file_size / total_time if total_time > 0 else 0
            
            result.update({
                "success": True,
                "encryption_time": encryption_time,
                "decryption_time": decryption_time,
                "total_time": total_time,
                "encryption_throughput": encryption_throughput,
                "decryption_throughput": decryption_throughput,
                "total_throughput": total_throughput,
                "original_hash": original_hash
            })
            
            print(f"  ✓ Success: Enc={encryption_time:.3f}s ({encryption_throughput/1024:.1f} KB/s), "
                  f"Dec={decryption_time:.3f}s ({decryption_throughput/1024:.1f} KB/s)")
            
            # 清理临时文件
            for f in [input_file, encrypted_file, decrypted_file]:
                if os.path.exists(f):
                    os.remove(f)
            
            return result
            
        except Exception as e:
            result["error"] = str(e)
            print(f"  ✗ Exception: {e}")
            return result
    
    def handle_exception(self, file_size: int, iteration: int, error: str):
        """处理异常情况"""
        print(f"\n⚠️ 异常发生!")
        print(f"  文件大小: {file_size} bytes")
        print(f"  迭代次数: {iteration}")
        print(f"  错误信息: {error}")
        print("\n请手动复位MCU，然后按回车键继续...")
        input()

    def run_test_suite(self, test_suite: List[Tuple[str, int, int]], 
                  needs_warmup: bool = False) -> List[Dict[str, Any]]:
        """运行一个测试套件（修改为出错重试当前迭代）"""
        suite_results = []
        
        for file_name, file_size, iterations in test_suite:
            print(f"\n{'='*60}")
            print(f"测试文件: {file_name} ({file_size} bytes)")
            print(f"{'='*60}")
            
            file_results = {
                "file_name": file_name,
                "file_size": file_size,
                "iterations": [],
                "summary": {}
            }
            
            for i in range(1, iterations + 1):
                current_iteration = i
                max_retries = 3  # 最大重试次数
                retry_count = 0
                iteration_completed = False
                iteration_result = None
                
                while not iteration_completed and retry_count <= max_retries:
                    # 小文件需要预热迭代
                    if needs_warmup and i == 1 and retry_count == 0:
                        print("  运行预热迭代...")
                        warmup_result = self.run_single_iteration(file_size, i, is_warmup=True)
                        
                        if not warmup_result["success"]:
                            print(f"  预热迭代失败: {warmup_result.get('error', 'Unknown error')}")
                            self.handle_exception(file_size, i, warmup_result.get('error', 'Warmup failed'))
                            retry_count += 1
                            continue
                    
                    # 主测试迭代
                    print(f"  运行迭代 {i}/{iterations}" + (f" (重试 {retry_count})" if retry_count > 0 else "") + "...")
                    main_result = self.run_single_iteration(file_size, i, is_warmup=(needs_warmup and i == 1))
                    
                    if main_result["success"]:
                        iteration_result = main_result
                        iteration_completed = True
                        print(f"  ✓ 迭代 {i} 成功完成")
                    else:
                        retry_count += 1
                        error_msg = main_result.get('error', 'Unknown error')
                        print(f"  ✗ 迭代 {i} 失败: {error_msg}")
                        
                        if retry_count <= max_retries:
                            print(f"  准备重试 ({retry_count}/{max_retries})...")
                            self.handle_exception_and_retry(file_size, i, error_msg, retry_count, max_retries)
                        else:
                            print(f"  ✗ 达到最大重试次数 ({max_retries})，放弃迭代 {i}")
                            iteration_result = main_result  # 记录失败结果
                            iteration_completed = True
                
                # 记录迭代结果（无论成功还是失败）
                if iteration_result is not None:
                    if not iteration_result["is_warmup"]:
                        file_results["iterations"].append(iteration_result)
            
            # 计算该文件的统计信息
            if file_results["iterations"]:
                successful_iterations = [r for r in file_results["iterations"] if r["success"]]
                if successful_iterations:
                    # 吞吐量统计
                    enc_throughputs = [r["encryption_throughput"] for r in successful_iterations]
                    dec_throughputs = [r["decryption_throughput"] for r in successful_iterations]
                    total_throughputs = [r["total_throughput"] for r in successful_iterations]
                    
                    file_results["summary"] = {
                        "successful_iterations": len(successful_iterations),
                        "failed_iterations": len(file_results["iterations"]) - len(successful_iterations),
                        "total_attempts": sum(r.get('attempts', 1) for r in file_results["iterations"]),
                        "avg_encryption_throughput": statistics.mean(enc_throughputs) if enc_throughputs else 0,
                        "max_encryption_throughput": max(enc_throughputs) if enc_throughputs else 0,
                        "min_encryption_throughput": min(enc_throughputs) if enc_throughputs else 0,
                        "std_encryption_throughput": statistics.stdev(enc_throughputs) if len(enc_throughputs) > 1 else 0,
                        "avg_decryption_throughput": statistics.mean(dec_throughputs) if dec_throughputs else 0,
                        "max_decryption_throughput": max(dec_throughputs) if dec_throughputs else 0,
                        "min_decryption_throughput": min(dec_throughputs) if dec_throughputs else 0,
                        "std_decryption_throughput": statistics.stdev(dec_throughputs) if len(dec_throughputs) > 1 else 0,
                        "avg_total_throughput": statistics.mean(total_throughputs) if total_throughputs else 0,
                        "max_total_throughput": max(total_throughputs) if total_throughputs else 0,
                        "min_total_throughput": min(total_throughputs) if total_throughputs else 0,
                        "std_total_throughput": statistics.stdev(total_throughputs) if len(total_throughputs) > 1 else 0
                    }
            
            suite_results.append(file_results)
        
        return suite_results

    def handle_exception_and_retry(self, file_size: int, iteration: int, error: str, 
                                retry_count: int, max_retries: int):
        """处理异常并准备重试"""
        print(f"\n⚠️ 异常发生!")
        print(f"  文件大小: {file_size} bytes")
        print(f"  迭代次数: {iteration}")
        print(f"  错误信息: {error}")
        print(f"  重试次数: {retry_count}/{max_retries}")
        print("\n请手动复位MCU，然后按回车键继续重试...")
        input()
    
    def calculate_overall_summary(self):
        """计算总体统计信息"""
        all_enc_throughputs = []
        all_dec_throughputs = []
        all_total_throughputs = []
        total_successful = 0
        total_failed = 0
        
        for test_case in self.results["test_cases"]:
            if "summary" in test_case and "successful_iterations" in test_case["summary"]:
                total_successful += test_case["summary"]["successful_iterations"]
                total_failed += test_case["summary"].get("failed_iterations", 0)
                
                # 收集所有吞吐量数据用于计算总体统计
                if test_case["iterations"]:
                    for iteration in test_case["iterations"]:
                        if iteration["success"]:
                            all_enc_throughputs.append(iteration["encryption_throughput"])
                            all_dec_throughputs.append(iteration["decryption_throughput"])
                            all_total_throughputs.append(iteration["total_throughput"])
        
        if all_enc_throughputs:
            self.results["summary"] = {
                "total_test_cases": len(self.results["test_cases"]),
                "total_successful_iterations": total_successful,
                "total_failed_iterations": total_failed,
                "success_rate": total_successful / (total_successful + total_failed) if (total_successful + total_failed) > 0 else 0,
                "overall_avg_encryption_throughput": statistics.mean(all_enc_throughputs),
                "overall_max_encryption_throughput": max(all_enc_throughputs),
                "overall_min_encryption_throughput": min(all_enc_throughputs),
                "overall_std_encryption_throughput": statistics.stdev(all_enc_throughputs) if len(all_enc_throughputs) > 1 else 0,
                "overall_avg_decryption_throughput": statistics.mean(all_dec_throughputs),
                "overall_max_decryption_throughput": max(all_dec_throughputs),
                "overall_min_decryption_throughput": min(all_dec_throughputs),
                "overall_std_decryption_throughput": statistics.stdev(all_dec_throughputs) if len(all_dec_throughputs) > 1 else 0,
                "overall_avg_total_throughput": statistics.mean(all_total_throughputs),
                "overall_max_total_throughput": max(all_total_throughputs),
                "overall_min_total_throughput": min(all_total_throughputs),
                "overall_std_total_throughput": statistics.stdev(all_total_throughputs) if len(all_total_throughputs) > 1 else 0
            }
    
    def display_results_table(self):
        """在终端显示结果表格（包含重试信息）"""
        print("\n" + "="*100)
        print(f"{self.project_name} 跑分结果汇总")
        print("="*100)
        
        # 总体统计
        if "summary" in self.results:
            summary = self.results["summary"]
            print(f"\n总体统计:")
            print(f"  成功迭代: {summary['total_successful_iterations']}")
            print(f"  失败迭代: {summary['total_failed_iterations']}")
            print(f"  总尝试次数: {summary.get('total_attempts', summary['total_successful_iterations'] + summary['total_failed_iterations'])}")
            print(f"  成功率: {summary['success_rate']*100:.1f}%")
            print(f"  平均加密吞吐量: {summary['overall_avg_encryption_throughput']/1024:.1f} KB/s")
            print(f"  平均解密吞吐量: {summary['overall_avg_decryption_throughput']/1024:.1f} KB/s")
            print(f"  平均总吞吐量: {summary['overall_avg_total_throughput']/1024:.1f} KB/s")
        
        # 详细表格
        print(f"\n详细结果:")
        print("-"*110)
        print(f"{'文件大小':<12} {'迭代':<6} {'状态':<10} {'尝试':<6} {'加密(KB/s)':<12} {'解密(KB/s)':<12} {'总(KB/s)':<12}")
        print("-"*110)
        
        for test_case in self.results["test_cases"]:
            file_name = test_case["file_name"]
            
            if test_case["iterations"]:
                for i, iteration in enumerate(test_case["iterations"]):
                    attempts = iteration.get("attempts", 1)
                    
                    if iteration["success"]:
                        enc_tp = iteration["encryption_throughput"] / 1024
                        dec_tp = iteration["decryption_throughput"] / 1024
                        total_tp = iteration["total_throughput"] / 1024
                        status = "✓ 成功"
                    else:
                        enc_tp = dec_tp = total_tp = 0
                        status = "✗ 失败"
                    
                    print(f"{file_name:<12} {i+1:<6} {status:<10} {attempts:<6} "
                        f"{enc_tp:<12.1f} {dec_tp:<12.1f} {total_tp:<12.1f}")
        
        print("-"*110)
    
    def save_results(self):
        """保存结果到JSON文件"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.output_dir, f"benchmark_{self.project_name}_{timestamp}.json")
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n结果已保存到: {filename}")
        return filename
    
    def run_full_benchmark(self):
        """运行完整的跑分测试"""
        print(f"{'='*60}")
        print(f"开始 {self.project_name} 跑分测试")
        print(f"串口: {self.port}")
        print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
        
        print("\n等待用户确认...")
        print("请确保已烧录正确的程序到MCU，然后按回车键开始测试")
        input()
        
        # 测试小文件（需要预热）
        print(f"\n{'#'*60}")
        print(f"第一阶段: 测试小文件 (需要预热迭代)")
        print(f"{'#'*60}")
        small_results = self.run_test_suite(self.small_files, needs_warmup=True)
        self.results["test_cases"].extend(small_results)
        
        # 测试中等文件
        print(f"\n{'#'*60}")
        print(f"第二阶段: 测试中等文件")
        print(f"{'#'*60}")
        medium_results = self.run_test_suite(self.medium_files, needs_warmup=False)
        self.results["test_cases"].extend(medium_results)
        
        # 测试大文件
        print(f"\n{'#'*60}")
        print(f"第三阶段: 测试大文件")
        print(f"{'#'*60}")
        large_results = self.run_test_suite(self.large_files, needs_warmup=False)
        self.results["test_cases"].extend(large_results)
        
        # 计算总体统计
        self.calculate_overall_summary()
        
        # 显示结果
        self.display_results_table()
        
        # 保存结果
        self.save_results()
        
        print(f"\n{'='*60}")
        print(f"{self.project_name} 跑分测试完成!")
        print(f"{'='*60}")

# 主函数 - 修改为交互式菜单
def main():
    print("=" * 60)
    print("GCM-SIV算法跑分测试框架")
    print("=" * 60)
    print("\n请选择测试项目:")
    print("1. 硬件AES-GCM-SIV (hardware_aes)")
    print("2. 软件AES-GCM-SIV (software_aes)")
    print("3. 软件Ascon (software_ascon)")
    print("\n0. 退出")
    
    choice = input("\n请选择 (0-3): ").strip()
    
    project_map = {
        "1": "hardware_aes",
        "2": "software_aes",
        "3": "software_ascon"
    }
    
    if choice == "0":
        print("退出程序")
        return
    
    if choice not in project_map:
        print("无效选择")
        return
    
    project_code = project_map[choice]
    
    # 项目名称映射
    project_names = {
        "hardware_aes": "硬件AES-GCM-SIV",
        "software_aes": "软件AES-GCM-SIV", 
        "software_ascon": "软件Ascon"
    }
    
    project_name = project_names.get(project_code, project_code)
    
    # 获取串口端口
    print("\n" + "-" * 60)
    port = input(f"请输入串口端口 (默认: COM3): ").strip()
    if not port:
        port = "COM3"
    
    # 获取输出目录
    output_dir = input(f"请输入输出目录 (默认: benchmark_results): ").strip()
    if not output_dir:
        output_dir = "benchmark_results"
    
    print("\n" + "=" * 60)
    print(f"配置信息:")
    print(f"  测试项目: {project_name}")
    print(f"  串口端口: {port}")
    print(f"  输出目录: {output_dir}")
    print("=" * 60)
    
    confirm = input("\n确认开始测试? (y/N): ").strip().lower()
    if confirm != 'y':
        print("测试取消")
        return
    
    # 创建并运行跑分测试
    runner = BenchmarkRunner(
        port=port,
        project_name=project_name,
        output_dir=output_dir
    )
    
    try:
        runner.run_full_benchmark()
    except KeyboardInterrupt:
        print("\n\n测试被用户中断")
    except Exception as e:
        print(f"\n测试发生错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()