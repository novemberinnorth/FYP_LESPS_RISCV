import serial
import time
import os
import base64
import struct

BaudRate = 115200

# NIST测试向量
NIST_TEST_VECTORS = {
    "CBC-AES128-Encrypt": {
        "key": bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        "iv": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "blocks": [
            {
                "plaintext": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
                "ciphertext": bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
            },
            {
                "plaintext": bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51"), 
                "ciphertext": bytes.fromhex("5086cb9b507219ee95db113a917678b2")
            },
            {
                "plaintext": bytes.fromhex("30c81c46a35ce411e5fbc1191a0a52ef"),
                "ciphertext": bytes.fromhex("73bed6b8e3c1743b7116e69e22229516")
            },
            {
                "plaintext": bytes.fromhex("f69f2445df4f9b17ad2b417be66c3710"),
                "ciphertext": bytes.fromhex("3ff1caa1681fac09120eca307586e1a7")
            }
        ]
    },
    "CBC-AES128-Decrypt": {
        "key": bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        "iv": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "blocks": [
            {
                "ciphertext": bytes.fromhex("7649abac8119b246cee98e9b12e9197d"),
                "plaintext": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
            },
            {
                "ciphertext": bytes.fromhex("5086cb9b507219ee95db113a917678b2"),
                "plaintext": bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51")
            },
            {
                "ciphertext": bytes.fromhex("73bed6b8e3c1743b7116e69e22229516"),
                "plaintext": bytes.fromhex("30c81c46a35ce411e5fbc1191a0a52ef")
            },
            {
                "ciphertext": bytes.fromhex("3ff1caa1681fac09120eca307586e1a7"),
                "plaintext": bytes.fromhex("f69f2445df4f9b17ad2b417be66c3710")
            }
        ]
    }
}

def nist_standard_test(port, test_name):
    """NIST标准化测试向量验证 - 完整数据块版本"""
    print(f"=== Starting NIST Standard Test: {test_name} ===")
    
    if test_name not in NIST_TEST_VECTORS:
        print(f"Unknown test: {test_name}")
        return False
    
    test_data = NIST_TEST_VECTORS[test_name]
    is_encrypt = "Encrypt" in test_name
    
    try:
        ser = serial.Serial(port, BaudRate, timeout=10, dsrdtr=False,  
                          write_timeout=10, xonxoff=False, rtscts=False)
        
        # 等待MCU启动完成
        print("Waiting for MCU to be ready...")
        start_time = time.time()
        while time.time() - start_time < 10:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'READY' in line:
                    print("MCU is ready")
                    break
        
        # 选择新的流式处理模式
        print("Selecting new stream mode...")
        ser.write(b'n')
        ser.flush()
        
        # 等待MCU进入新模式
        print("Waiting for MCU to enter new stream mode...")
        start_time = time.time()
        while time.time() - start_time < 10:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'NEW_STREAM_MODE' in line:
                    print("MCU entered new stream mode")
                    break
        
        # 等待操作选择提示
        print("Waiting for operation prompt...")
        start_time = time.time()
        while time.time() - start_time < 10:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'WAIT_OPERATION' in line:
                    print("Sending operation...")
                    break
        
        # 发送操作模式
        if is_encrypt:
            ser.write(b'e')
            print("Sent operation: encrypt")
        else:
            ser.write(b'd')
            print("Sent operation: decrypt")
        ser.flush()
        
        # 等待确认
        print("Waiting for ACK...")
        start_time = time.time()
        while time.time() - start_time < 10:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'ACK' in line:
                    print("Operation accepted")
                    break
        
        # 发送密钥
        print("Sending key...")
        key = test_data["key"]
        ser.write(key)
        ser.flush()
        
        # 等待密钥确认
        print("Waiting for key ACK...")
        start_time = time.time()
        while time.time() - start_time < 10:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'ACK' in line:
                    print("Key accepted")
                    break
        
        # 发送IV
        print("Sending IV...")
        iv = test_data["iv"]
        ser.write(iv)
        ser.flush()
        
        # 等待IV确认
        print("Waiting for IV ACK...")
        start_time = time.time()
        while time.time() - start_time < 10:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'ACK' in line:
                    print("IV accepted")
                    break
        
        # 准备完整的测试数据（64字节）
        if is_encrypt:
            # 合并所有明文块
            input_data = b''.join([block["plaintext"] for block in test_data["blocks"]])
            expected_output = b''.join([block["ciphertext"] for block in test_data["blocks"]])
            print(f"Complete Plaintext:  {input_data.hex()}")
            print(f"Expected Ciphertext: {expected_output.hex()}")
        else:
            # 合并所有密文块
            input_data = b''.join([block["ciphertext"] for block in test_data["blocks"]])
            expected_output = b''.join([block["plaintext"] for block in test_data["blocks"]])
            print(f"Complete Ciphertext: {input_data.hex()}")
            print(f"Expected Plaintext:  {expected_output.hex()}")
        
        # 发送文件大小 (64字节)
        file_size = len(input_data)
        size_data = struct.pack('>I', file_size)
        ser.write(size_data)
        ser.flush()
        
        # 等待文件大小确认
        print("Waiting for file size ACK...")
        start_time = time.time()
        while time.time() - start_time < 10:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'ACK' in line:
                    print("File size accepted")
                    break
        
        # 等待数据就绪
        print("Waiting for MCU to be ready for data...")
        start_time = time.time()
        while time.time() - start_time < 10:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'READY_FOR_DATA' in line:
                    print("MCU is ready for data")
                    break
        
        # 等待块请求
        print("Waiting for chunk request...")
        start_time = time.time()
        while time.time() - start_time < 10:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'WAIT_CHUNK' in line:
                    requested_size = int(line.split(':')[1])
                    print(f"Sending {requested_size} bytes data chunk...")
                    break
        
        # 发送完整数据
        bytes_sent = 0
        block_size = 64  # 每次发送64字节
        while bytes_sent < len(input_data):
            end_pos = min(bytes_sent + block_size, len(input_data))
            block = input_data[bytes_sent:end_pos]
            ser.write(block)
            ser.flush()
            bytes_sent += len(block)
            time.sleep(0.02)
        
        # 等待处理结果
        print("Waiting for processed data...")
        start_time = time.time()
        actual_output = b''
        
        while time.time() - start_time < 30:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                
                if line.startswith('B64:'):
                    b64_data = line[4:]
                    try:
                        # Base64解码
                        padding_needed = len(b64_data) % 4
                        if padding_needed:
                            b64_data += '=' * (4 - padding_needed)
                        chunk_output = base64.b64decode(b64_data)
                        actual_output += chunk_output
                        print(f"Received chunk: {len(chunk_output)} bytes")
                        
                    except Exception as e:
                        print(f"Base64 decode error: {e}")
                
                if 'STREAM_COMPLETE' in line:
                    print("Stream completed")
                    break
        
        print(f"Complete Actual Output: {actual_output.hex()}")
        
        # 验证完整结果
        if actual_output == expected_output:
            print("✓ ALL BLOCKS PASS - Complete test successful")
            return True
        else:
            print("✗ FAIL - Complete output mismatch")
            # 分块验证
            passed_blocks = 0
            total_blocks = len(test_data["blocks"])
            for i in range(total_blocks):
                start_idx = i * 16
                end_idx = start_idx + 16
                actual_block = actual_output[start_idx:end_idx] if len(actual_output) >= end_idx else b''
                
                if is_encrypt:
                    expected_block = test_data["blocks"][i]["ciphertext"]
                    block_type = "Ciphertext"
                else:
                    expected_block = test_data["blocks"][i]["plaintext"]
                    block_type = "Plaintext"
                
                if actual_block == expected_block:
                    print(f"  Block {i+1}: ✓ {block_type} correct")
                    passed_blocks += 1
                else:
                    print(f"  Block {i+1}: ✗ {block_type} mismatch")
                    print(f"    Expected: {expected_block.hex()}")
                    print(f"    Actual:   {actual_block.hex()}")
            
            print(f"Block-level result: {passed_blocks}/{total_blocks} blocks passed")
            return False
            
    except Exception as e:
        print(f"Error during NIST test: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if 'ser' in locals():
            ser.close()

def new_stream_file_processing_with_key_iv(port, operation, custom_key=None, custom_iv=None):
    """支持自定义密钥和IV的流式文件处理"""
    
    input_file = "input.txt" if operation == "encrypt" else "ciphertext.txt"
    output_file = "ciphertext.txt" if operation == "encrypt" else "output.txt"
    
    # 默认密钥和IV
    default_key = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
    default_iv = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
    
    key = custom_key if custom_key else default_key
    iv = custom_iv if custom_iv else default_iv
    
    if not os.path.exists(input_file):
        print(f"Input file does not exist: {input_file}")
        return False
    
    try:
        ser = serial.Serial(port, BaudRate, timeout=10, dsrdtr=False,  
                          write_timeout=10, xonxoff=False, rtscts=False)
        
        # ... (前面的握手过程与原来相同)
        
        # 在发送操作后，添加密钥和IV发送
        # 发送密钥
        print("Sending key...")
        ser.write(key)
        ser.flush()
        
        # 等待密钥确认
        print("Waiting for key ACK...")
        start_time = time.time()
        while time.time() - start_time < 10:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'ACK' in line:
                    print("Key accepted")
                    break
        
        # 发送IV
        print("Sending IV...")
        ser.write(iv)
        ser.flush()
        
        # 等待IV确认
        print("Waiting for IV ACK...")
        start_time = time.time()
        while time.time() - start_time < 10:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'ACK' in line:
                    print("IV accepted")
                    break
        
        # ... (后续的文件处理流程与原来相同)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        if 'ser' in locals():
            ser.close()
        return False

def auto_mode_continuous(port):
    """连续自动模式：加密 -> 解密 -> 对比"""
    print("=== Starting Continuous Auto Mode: Encrypt -> Decrypt -> Compare ===")
    
    try:
        ser = serial.Serial(port, BaudRate, timeout=10, dsrdtr=False,  
                          write_timeout=10, xonxoff=False, rtscts=False)
        
        # 等待MCU启动完成
        print("Waiting for MCU to be ready...")
        start_time = time.time()
        while time.time() - start_time < 10:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if 'READY' in line:
                    print("MCU is ready")
                    break
        
        # 步骤1: 加密
        print("\n--- Step 1: Encrypting input.txt -> ciphertext.txt ---")
        if process_operation_continuous(ser, "encrypt"):
            print("✓ Encryption completed successfully")
            
            # 步骤2: 解密
            print("\n--- Step 2: Decrypting ciphertext.txt -> output.txt ---")
            if process_operation_continuous(ser, "decrypt"):
                print("✓ Decryption completed successfully")
                
                # 步骤3: 文件对比
                print("\n--- Step 3: Comparing input.txt and output.txt ---")
                verify_files("input.txt", "output.txt")
            else:
                print("✗ Decryption failed, skipping file comparison")
        else:
            print("✗ Encryption failed, skipping decryption and comparison")
        
        ser.close()
        print("\n=== Continuous Auto Mode Completed ===")
        return True
        
    except Exception as e:
        print(f"Error in continuous auto mode: {e}")
        if 'ser' in locals():
            ser.close()
        return False

def process_operation_continuous(ser, operation):
    """在已建立的连接上处理操作（支持密钥和IV）"""
    
    input_file = "input.txt" if operation == "encrypt" else "ciphertext.txt"
    output_file = "ciphertext.txt" if operation == "encrypt" else "output.txt"
    
    # 默认密钥和IV
    default_key = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
    default_iv = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
    
    # 选择新的流式处理模式
    print("Selecting new stream mode...")
    ser.write(b'n')
    ser.flush()
    
    # 等待MCU进入新模式
    print("Waiting for MCU to enter new stream mode...")
    start_time = time.time()
    while time.time() - start_time < 10:
        if ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if 'NEW_STREAM_MODE' in line:
                print("MCU entered new stream mode")
                break
            if 'ERROR' in line:
                print(f"MCU error: {line}")
                return False
    
    # 等待操作选择提示
    print("Waiting for operation prompt...")
    start_time = time.time()
    while time.time() - start_time < 10:
        if ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if 'WAIT_OPERATION' in line:
                print("Sending operation...")
                break
    
    # 发送操作模式
    if operation == "encrypt":
        ser.write(b'e')
    else:
        ser.write(b'd')
    ser.flush()
    print(f"Sent operation: {operation}")
    
    # 等待确认
    print("Waiting for ACK...")
    start_time = time.time()
    while time.time() - start_time < 10:
        if ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if 'ACK' in line:
                print("Operation accepted")
                break
            if 'ERROR' in line:
                print(f"Operation error: {line}")
                return False
    
    # 发送默认密钥
    print("Sending default key...")
    ser.write(default_key)
    ser.flush()
    
    # 等待密钥确认
    print("Waiting for key ACK...")
    start_time = time.time()
    while time.time() - start_time < 10:
        if ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if 'ACK' in line:
                print("Key accepted")
                break
    
    # 发送默认IV
    print("Sending default IV...")
    ser.write(default_iv)
    ser.flush()
    
    # 等待IV确认
    print("Waiting for IV ACK...")
    start_time = time.time()
    while time.time() - start_time < 10:
        if ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if 'ACK' in line:
                print("IV accepted")
                break
    
    # 读取输入文件
    with open(input_file, 'rb') as f:
        file_data = f.read()
    
    file_size = len(file_data)
    print(f"Processing file: {input_file} ({file_size} bytes)")
    
    # 等待文件大小提示
    print("Waiting for file size prompt...")
    start_time = time.time()
    size_prompt_received = False
    while time.time() - start_time < 15:
        if ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if 'WAIT_SIZE' in line:
                print("Sending file size...")
                size_prompt_received = True
                break
            if 'ERROR' in line:
                print(f"MCU error before size: {line}")
                return False

    if not size_prompt_received:
        print("File size prompt timeout")
        return False

    # 发送文件大小前短暂延迟
    time.sleep(0.1)

    # 发送文件大小 (4字节大端序)
    size_data = struct.pack('>I', file_size)
    print(f"Sending file size: {file_size} bytes")

    # 逐字节发送文件大小
    for i in range(4):
        ser.write(size_data[i:i+1])
        ser.flush()
        time.sleep(0.01)

    print("File size sent completely")
    
    # 等待文件大小确认
    print("Waiting for file size ACK...")
    start_time = time.time()
    while time.time() - start_time < 10:
        if ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if 'ACK' in line:
                print("File size accepted")
                break
            if 'ERROR' in line:
                print(f"File size error: {line}")
                return False
    
    # 等待数据就绪
    print("Waiting for MCU to be ready for data...")
    start_time = time.time()
    while time.time() - start_time < 10:
        if ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if 'READY_FOR_DATA' in line:
                print("MCU is ready for data")
                break
    
    # 分块发送数据 - 关键修改：解密时使用加密后的实际块大小
    total_sent = 0
    chunk_count = 0
    
    with open(output_file, 'wb') as out_f:
        while total_sent < file_size:
            chunk_count += 1
            remaining = file_size - total_sent
            
            # 等待块请求并获取请求的块大小
            print(f"Waiting for chunk request {chunk_count}...")
            start_time = time.time()
            chunk_request_received = False
            requested_size = 0
            while time.time() - start_time < 10:
                if ser.in_waiting > 0:
                    line = ser.readline().decode('utf-8', errors='ignore').strip()
                    if 'WAIT_CHUNK' in line:
                        # 提取请求的块大小
                        try:
                            requested_size = int(line.split(':')[1])
                            print(f"MCU requested chunk of {requested_size} bytes")
                            
                            # 验证请求的大小是否合理
                            if requested_size > remaining:
                                requested_size = remaining
                            
                            chunk_request_received = True
                            break
                        except (ValueError, IndexError):
                            # 使用默认块大小
                            requested_size = min(remaining, 128)
                            chunk_request_received = True
                            break
            
            if not chunk_request_received:
                print("Chunk request timeout")
                break
            
            # 准备数据块
            current_chunk_size = requested_size
            chunk = file_data[total_sent:total_sent + current_chunk_size]
            
            print(f"Sending chunk {chunk_count}: {len(chunk)} bytes")
            
            # 批量发送，提高效率
            bytes_sent = 0
            block_size = 64  # 每次发送64字节
            while bytes_sent < len(chunk):
                end_pos = min(bytes_sent + block_size, len(chunk))
                block = chunk[bytes_sent:end_pos]
                ser.write(block)
                ser.flush()
                bytes_sent += len(block)
                time.sleep(0.02)  # 每块之间短暂延迟
            
            total_sent += len(chunk)
            
            # 等待块接收确认
            print("Waiting for chunk reception...")
            start_time = time.time()
            chunk_received = False
            
            while time.time() - start_time < 60:
                if ser.in_waiting > 0:
                    line = ser.readline().decode('utf-8', errors='ignore').strip()
                    
                    if 'CHUNK_RECEIVED' in line:
                        try:
                            received_size = int(line.split(':')[1])
                            if received_size == len(chunk):
                                chunk_received = True
                                print("✓ Chunk received by MCU")
                            else:
                                print(f"Size mismatch: sent {len(chunk)}, MCU received {received_size}")
                        except (ValueError, IndexError):
                            print(f"Failed to parse CHUNK_RECEIVED: {line}")
                        break
                    if 'PROGRESS' in line:
                        print(f"MCU progress: {line}")
                    if 'ERROR' in line:
                        print(f"MCU error: {line}")
                        break
            
            if not chunk_received:
                print("⚠ Chunk reception timeout")
            
            # 等待处理结果
            print("Waiting for processed data...")
            start_time = time.time()
            processed_data = None
            b64_data = ""
            base64_received = False
            expected_b64_len = None  # 初始化为None

            while time.time() - start_time < 60:
                if ser.in_waiting > 0:
                    line = ser.readline().decode('utf-8', errors='ignore').strip()
                    
                    # 检查Base64长度信息（Ascon项目特有）
                    if line.startswith('B64_LEN:'):
                        expected_b64_len = int(line.split(':')[1])
                        print(f"Expected Base64 length: {expected_b64_len}")
                        continue

                    # 检查是否是Base64数据行（通用）
                    if line.startswith('B64:'):
                        b64_data = line[4:]  # 移除"B64:"前缀
                        actual_b64_len = len(b64_data)
                        print(f"✓ Received Base64 data, length: {actual_b64_len}")
                        
                        # 通用处理：不依赖B64_LEN，直接尝试解码
                        base64_received = True
                        
                        # 立即尝试解码
                        try:
                            # 确保Base64字符串长度是4的倍数
                            padding_needed = len(b64_data) % 4
                            if padding_needed:
                                b64_data += '=' * (4 - padding_needed)
                            
                            processed_data = base64.b64decode(b64_data)
                            print(f"✓ Successfully decoded Base64: {len(processed_data)} bytes")
                            break
                        except Exception as e:
                            print(f"✗ Base64 decode error: {e}")
                            print(f"  Problematic Base64 data: {b64_data[:100]}...")
                            continue
                    
                    if 'CHUNK_PROCESSED' in line:
                        print("✓ Chunk processing completed")
                        # 如果已经收到Base64数据但还没解码成功，再次尝试
                        if base64_received and not processed_data:
                            try:
                                padding_needed = len(b64_data) % 4
                                if padding_needed:
                                    b64_data += '=' * (4 - padding_needed)
                                processed_data = base64.b64decode(b64_data)
                                print(f"✓ Decoded Base64 after CHUNK_PROCESSED: {len(processed_data)} bytes")
                                break
                            except Exception as e:
                                print(f"✗ Base64 decode error after CHUNK_PROCESSED: {e}")
                    
                    if 'PROGRESS' in line:
                        print(f"Progress: {line}")
                    
                    if 'ERROR' in line:
                        print(f"MCU error: {line}")
                        break
                    
                    if 'STREAM_COMPLETE' in line:
                        print("Stream completed")
                        break
            
            if processed_data:
                out_f.write(processed_data)
                out_f.flush()
                print(f"✓ Written {len(processed_data)} bytes to output file")
            else:
                print("✗ No processed data received")
            
            progress = (total_sent / file_size) * 100
            print(f"Overall progress: {progress:.1f}%")
            
            if total_sent >= file_size:
                break
    
    # 等待流处理完成
    print("Waiting for stream completion...")
    start_time = time.time()
    while time.time() - start_time < 30:
        if ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if 'STREAM_COMPLETE' in line:
                print("✓ Stream processing completed")
                break
            if 'SUMMARY' in line or 'SUCCESS' in line or 'WARNING' in line:
                print(f"MCU: {line}")
    
    print(f"Processing completed. Output: {output_file}")
    
    # 验证输出文件
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        output_size = os.path.getsize(output_file)
        print(f"✓ {operation.capitalize()} successful: {output_file} created with {output_size} bytes")
        return True
    else:
        print(f"✗ {operation.capitalize()} failed: {output_file} is empty or missing")
        return False

def verify_files(file1=None, file2=None):
    """验证两个文件是否相同"""
    # 设置默认文件路径
    file1_default = "input.txt"
    file2_default = "output.txt"
    
    # 如果提供了文件参数，直接使用（用于自动模式）
    if file1 is not None and file2 is not None:
        # 直接比较模式，不等待用户输入
        print(f"Comparing files: {file1} vs {file2}")
    else:
        # 交互模式，提示用户输入
        if file1 is None:
            user_input = input(f"Enter first file path [{file1_default}]: ").strip()
            file1 = user_input if user_input else file1_default
        
        if file2 is None:
            user_input = input(f"Enter second file path [{file2_default}]: ").strip()
            file2 = user_input if user_input else file2_default
    
    if not os.path.exists(file1):
        print(f"File does not exist: {file1}")
        return False
    if not os.path.exists(file2):
        print(f"File does not exist: {file2}")
        return False
        
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
                
                # 找出差异位置
                min_len = min(len(content1), len(content2))
                differences = 0
                first_diff = -1
                for i in range(min_len):
                    if content1[i] != content2[i]:
                        differences += 1
                        if first_diff == -1:
                            first_diff = i
                
                if differences > 0:
                    print(f"  Found {differences} differences")
                    print(f"  First difference at byte position: {first_diff}")
                    if first_diff >= 0:
                        print(f"  {file1} byte {first_diff}: 0x{content1[first_diff]:02x}")
                        print(f"  {file2} byte {first_diff}: 0x{content2[first_diff]:02x}")
                
                if len(content1) != len(content2):
                    print(f"  File size difference: {abs(len(content1) - len(content2))} bytes")
                
                return False
    except Exception as e:
        print(f"Error verifying files: {e}")
        return False

def legacy_modes(port):
    """原有的legacy模式"""
    print("Legacy modes not implemented in this version")
    # 这里可以添加原有的legacy模式代码

def main():
    port = "COM3"
    
    print("File Encryption/Decryption System")
    print("1. Encrypt input.txt -> ciphertext.txt (New Stream Mode)")
    print("2. Decrypt ciphertext.txt -> output.txt (New Stream Mode)")
    print("3. Compare two files")
    print("4. NIST Standard Test: CBC-AES128 Encrypt")
    print("5. NIST Standard Test: CBC-AES128 Decrypt")
    print("6. Auto Continuous: Encrypt -> Decrypt -> Compare (no reset)")
    print("7. Legacy modes")
    
    choice = input("Choose operation (1-7): ").strip()
    
    if choice == "1":
        new_stream_file_processing_with_key_iv(port, "encrypt")
    elif choice == "2":
        new_stream_file_processing_with_key_iv(port, "decrypt")
    elif choice == "3":
        verify_files()
    elif choice == "4":
        nist_standard_test(port, "CBC-AES128-Encrypt")
    elif choice == "5":
        nist_standard_test(port, "CBC-AES128-Decrypt")
    elif choice == "6":
        auto_mode_continuous(port)
    elif choice == "7":
        legacy_modes(port)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()