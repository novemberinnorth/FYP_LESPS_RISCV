import serial
import time
import os
import base64
import struct

BaudRate = 115200

def new_stream_file_processing(port, operation):
    """全新的流式文件处理 - 使用可靠的文本协议"""
    
    input_file = "input.txt" if operation == "encrypt" else "ciphertext.txt"
    output_file = "ciphertext.txt" if operation == "encrypt" else "output.txt"
    
    if not os.path.exists(input_file):
        print(f"Input file does not exist: {input_file}")
        return False
    
    try:
        ser = serial.Serial(port, BaudRate, timeout=10, dsrdtr=False,  
                          write_timeout=10, xonxoff=False, rtscts=False)
        # 清空缓冲区
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        
        print(f"Port {port} opened at {BaudRate} baud")
        
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
        ser.write(b'n')  # 使用新的流式模式
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
        
        # 读取输入文件
        with open(input_file, 'rb') as f:
            file_data = f.read()
        
        file_size = len(file_data)
        print(f"Processing file: {input_file} ({file_size} bytes)")
        
        # 等待文件大小提示
        print("Waiting for file size prompt...")
        start_time = time.time()
        size_prompt_received = False
        while time.time() - start_time < 15:  # 增加超时时间
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

        # 逐字节发送文件大小，确保可靠性
        for i in range(4):
            ser.write(size_data[i:i+1])
            ser.flush()
            time.sleep(0.01)  # 10ms延迟 between bytes

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
        
        # 分块发送数据 - 根据MCU请求动态调整块大小
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
                
                # 根据MCU请求的大小准备数据块
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
                    # 不立即退出，继续尝试等待处理结果
                
                # 等待处理结果
                print("Waiting for processed data...")
                start_time = time.time()
                processed_data = None
                b64_data = ""
                base64_received = False
                
                while time.time() - start_time < 60:
                    if ser.in_waiting > 0:
                        line = ser.readline().decode('utf-8', errors='ignore').strip()
                        
                        # 检查是否是Base64数据行
                        if line.startswith('B64:'):
                            b64_data = line[4:]  # 移除"B64:"前缀
                            print(f"✓ Received Base64 data, length: {len(b64_data)}")
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
        
        # 仅在加密模式下验证输出文件是否存在
        if operation == "encrypt":
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                output_size = os.path.getsize(output_file)
                print(f"✓ Encryption successful: {output_file} created with {output_size} bytes")
            else:
                print(f"✗ Encryption failed: {output_file} is empty or missing")
        else:
            # 解密模式下只确认文件创建
            if os.path.exists(output_file):
                output_size = os.path.getsize(output_file)
                print(f"✓ Decryption completed: {output_file} created with {output_size} bytes")
            else:
                print(f"✗ Decryption failed: {output_file} is missing")
        
        ser.close()
        return True
        
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
    """在已建立的连接上处理操作"""

    input_file = "input.txt" if operation == "encrypt" else "ciphertext.txt"
    output_file = "ciphertext.txt" if operation == "encrypt" else "output.txt"
    
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
    
    # 读取输入文件
    with open(input_file, 'rb') as f:
        file_data = f.read()
    
    file_size = len(file_data)
    print(f"Processing file: {input_file} ({file_size} bytes)")
    
    # 等待文件大小提示
    print("Waiting for file size prompt...")
    start_time = time.time()
    size_prompt_received = False
    while time.time() - start_time < 15:  # 增加超时时间
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

    # 逐字节发送文件大小，确保可靠性
    for i in range(4):
        ser.write(size_data[i:i+1])
        ser.flush()
        time.sleep(0.01)  # 10ms延迟 between bytes

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
    
    # 分块发送数据 - 根据MCU请求动态调整块大小
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
            
            # 根据MCU请求的大小准备数据块
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
                # 不立即退出，继续尝试等待处理结果
            
            # 等待处理结果
            print("Waiting for processed data...")
            start_time = time.time()
            processed_data = None
            b64_data = ""
            base64_received = False
            
            while time.time() - start_time < 60:
                if ser.in_waiting > 0:
                    line = ser.readline().decode('utf-8', errors='ignore').strip()
                    
                    # 检查是否是Base64数据行
                    if line.startswith('B64:'):
                        b64_data = line[4:]  # 移除"B64:"前缀
                        print(f"✓ Received Base64 data, length: {len(b64_data)}")
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
    
    # 仅在加密模式下验证输出文件是否存在
    if operation == "encrypt":
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            output_size = os.path.getsize(output_file)
            print(f"✓ Encryption successful: {output_file} created with {output_size} bytes")
        else:
            print(f"✗ Encryption failed: {output_file} is empty or missing")
    else:
        # 解密模式下只确认文件创建
        if os.path.exists(output_file):
            output_size = os.path.getsize(output_file)
            print(f"✓ Decryption completed: {output_file} created with {output_size} bytes")
        else:
            print(f"✗ Decryption failed: {output_file} is missing")
    
    return True

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
    print("4. Auto: Encrypt -> Decrypt -> Compare (with reset)")
    print("5. Auto Continuous: Encrypt -> Decrypt -> Compare (no reset)")
    print("6. Legacy modes")
    
    choice = input("Choose operation (1-6): ").strip()
    
    if choice == "1":
        new_stream_file_processing(port, "encrypt")
    elif choice == "2":
        new_stream_file_processing(port, "decrypt")
    elif choice == "3":
        # 文件对比功能
        verify_files()
    elif choice == "4":
        # 自动执行加密、解密、文件对比
        print("=== Starting Auto Mode: Encrypt -> Decrypt -> Compare ===")
        
        # 步骤1: 加密
        print("\n--- Step 1: Encrypting input.txt -> ciphertext.txt ---")
        if new_stream_file_processing(port, "encrypt"):
            print("✓ Encryption completed successfully")
            
            # 步骤2: 解密
            print("\n--- Step 2: Decrypting ciphertext.txt -> output.txt ---")
            if new_stream_file_processing(port, "decrypt"):
                print("✓ Decryption completed successfully")
                
                # 步骤3: 文件对比
                print("\n--- Step 3: Comparing input.txt and output.txt ---")
                verify_files("input.txt", "output.txt")
            else:
                print("✗ Decryption failed, skipping file comparison")
        else:
            print("✗ Encryption failed, skipping decryption and comparison")
        
        print("\n=== Auto Mode Completed ===")
    elif choice == "5":
        # 新的连续自动模式（不需要复位）
        auto_mode_continuous(port)
    elif choice == "6":
        legacy_modes(port)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()