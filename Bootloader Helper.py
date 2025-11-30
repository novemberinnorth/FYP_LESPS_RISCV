import serial
import threading
import time
import sys
import os
from xmodem import XMODEM
import subprocess
import tempfile

class TeraTermXMODEM:
    """使用Tera Term进行XMODEM传输"""
    
    def __init__(self, port='COM3', baudrate=115200):
        self.port = port
        self.baudrate = baudrate
        
    def send_file(self, file_path):
        """使用Tera Term发送文件"""
        # 创建临时宏文件
        macro_content = f'''
connect = '{self.port}:{self.baudrate}'
wait 'Waiting for the file to be sent'
xmodem send '{file_path}'
pause 2
quit
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ttl', delete=False) as f:
            macro_file = f.name
            f.write(macro_content)
        
        try:
            # 执行Tera Term
            cmd = f'D:\teraterm5\ttermpro.exe"{macro_file}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Tera Term传输成功!")
                return True
            else:
                print(f"❌ Tera Term传输失败: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ 执行Tera Term时出错: {e}")
            return False
        finally:
            # 清理临时文件
            try:
                os.unlink(macro_file)
            except:
                pass

class BootloaderManager:
    def __init__(self, port='COM3', baudrate=115200):
        self.communicator = MCUCommunicator(port, baudrate)
        self.xmodem_transferring = False
        self.communicator.on_enter_download_mode = self._on_enter_download_mode
        
    def start(self):
        """启动bootloader管理器"""
        self.communicator.start_communication()
    
    def _on_enter_download_mode(self):
        """进入下载模式回调"""
        print("🎯 进入XMODEM下载模式...")
        
        # 自动查找固件文件
        firmware_path = "D:/My_Workspace/NucleiStudio_workspace/test_Bootloader_user/Debug/test_bootloader_user.bin"
        if firmware_path:
            print(f"🔍 自动找到固件文件: {firmware_path}")
            self._start_xmodem_transfer(firmware_path)
        else:
            firmware_path = input("请输入固件文件路径: ").strip()
            if os.path.exists(firmware_path):
                self._start_xmodem_transfer(firmware_path)
            else:
                print(f"❌ 文件不存在: {firmware_path}")
                self.communicator.menu_detected = True
    
    def _find_firmware_file(self):
        """自动查找固件文件"""
        # 常见固件文件位置
        common_paths = [
            "Debug/test_bootloader_user.bin",
            "Debug/IAP_User.bin", 
            "test_bootloader_user.bin",
            "IAP_User.bin",
            "../test_Bootloader_user/Debug/test_bootloader_user.bin",
            "../IAP_User/Debug/IAP_User.bin"
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        return None
    
    def _start_xmodem_transfer(self, file_path):
        """使用Tera Term进行XMODEM传输"""
        print(f"📤 使用Tera Term传输文件: {file_path}")
        
        tera_term = TeraTermXMODEM(port='COM3', baudrate=115200)
        success = tera_term.send_file(file_path)
        
        if success:
            print("✅ 文件传输成功!")
            time.sleep(2)
            self.communicator.menu_detected = True
            self.communicator.waiting_for_xmodem = False
        else:
            print("❌ 文件传输失败!")
            self.communicator.menu_detected = True
            self.communicator.waiting_for_xmodem = False

class MCUCommunicator:
    def __init__(self, port='COM3', baudrate=115200, timeout=2):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.ser = None
        self.running = False
        self.menu_detected = False
        self.on_enter_download_mode = None
        self.waiting_for_xmodem = False
        self.download_triggered = False
        
    def connect(self):
        """连接串口"""
        try:
            self.ser = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=self.timeout
            )
            print(f"✅ 已连接到 {self.port}")
            # 清空缓冲区
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            return True
        except serial.SerialException as e:
            print(f"❌ 无法连接到 {self.port}: {e}")
            return False
    
    def start_communication(self):
        """启动通信"""
        if not self.connect():
            return
        
        self.running = True
        
        # 启动读取线程
        read_thread = threading.Thread(target=self._read_serial)
        read_thread.daemon = True
        read_thread.start()
        
        print("⏳ 等待MCU启动并显示菜单...")
        
        # 主线程处理用户输入
        self._handle_user_input()
    
    def _read_serial(self):
        """读取串口数据并显示"""
        buffer = ""
        while self.running:
            try:
                if self.ser and self.ser.in_waiting > 0:
                    data = self.ser.read(self.ser.in_waiting).decode('utf-8', errors='ignore')
                    buffer += data
                    
                    # 处理完整的行
                    while '\n' in buffer or '\r' in buffer:
                        if '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)
                        else:
                            line, buffer = buffer.split('\r', 1)
                        line = line.strip()
                        if line:
                            self._process_received_line(line)
                
                time.sleep(0.01)
            except Exception as e:
                print(f"读取串口数据时出错: {e}")
                break
    
    def _process_received_line(self, line):
        """增强的处理接收行方法"""
        # 过滤掉单个字符的噪声
        if len(line) == 1 and line in ['C', 'N', 'G']:
            if self.waiting_for_xmodem:
                print(f"🔧 XMODEM协议字符: {line}")
                # 如果是'C'字符且正在等待XMODEM，触发下载
                if line == 'C' and not self.download_triggered:
                    self.download_triggered = True
                    if self.on_enter_download_mode:
                        self.on_enter_download_mode()
                return
        
        print(f"MCU: {line}")
        
        # 检测菜单标题
        if "Main Menu" in line:
            self.menu_detected = True
            self.waiting_for_xmodem = False
            self.download_triggered = False
            self._show_input_prompt()
        elif "===================" in line and "Main Menu" in line:
            self.menu_detected = True
            self.waiting_for_xmodem = False
            self.download_triggered = False
        # 检测菜单选项
        elif "Download image to the internal Flash" in line:
            print("📥 选项1: 下载固件到内部Flash")
        elif "Execute the loaded application" in line:
            print("🚀 选项2: 执行已加载的应用程序")
            self._show_input_prompt()
        # 检测等待文件传输的信号
        elif "Waiting for the file to be sent" in line:
            print("🔧 检测到文件传输等待信号")
            self.waiting_for_xmodem = True
            # 如果MCU没有主动发送'C'字符，我们等待一小段时间后主动触发传输
            if not self.download_triggered:
                print("⏳ MCU已准备好，等待XMODEM起始信号...")
                # 启动一个定时器，如果没有收到'C'字符，在2秒后主动开始传输
                timer = threading.Timer(2.0, self._trigger_download_if_needed)
                timer.daemon = True
                timer.start()
        # 检测错误信息
        elif "Invalid Number" in line:
            print("❌ MCU报告: 无效输入")
            self.menu_detected = True
            self._show_input_prompt()
        elif "Failed to receive the file" in line:
            print("❌ MCU报告: 文件接收失败")
            self.menu_detected = True
            self.waiting_for_xmodem = False
            self._show_input_prompt()
    
    def _trigger_download_if_needed(self):
        """如果没有收到XMODEM起始信号，主动触发下载"""
        if self.waiting_for_xmodem and not self.download_triggered:
            print("🔄 未收到XMODEM起始信号，主动开始传输...")
            self.download_triggered = True
            if self.on_enter_download_mode:
                self.on_enter_download_mode()
    
    def _show_input_prompt(self):
        """显示用户输入提示"""
        if self.menu_detected and not self.waiting_for_xmodem:
            print("\n" + "="*50)
            print("💡 请输入您的选择:")
            print("  1 - 下载固件")
            print("  2 - 执行应用程序")
            print("  q - 退出")
            print("="*50)
    
    def _handle_user_input(self):
        """处理用户输入"""
        try:
            while self.running:
                if self.menu_detected and not self.waiting_for_xmodem:
                    # 使用简单的input，因为非阻塞方式在Windows上有问题
                    try:
                        choice = input("\n请输入选择 (1/2/q): ").strip().lower()
                        self._process_user_choice(choice)
                    except EOFError:
                        # 在有些环境下input可能会抛出EOFError
                        time.sleep(0.1)
                        continue
                
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print("\n👋 用户中断程序")
        finally:
            self.close()
    
    def _process_user_choice(self, choice):
        """增强的用户选择处理"""
        if choice == '1':
            print("📤 选择: 下载模式")
            self._send_command('1')
            self.menu_detected = False
            self.waiting_for_xmodem = True
            self.download_triggered = False
            print("⏳ 等待XMODEM传输准备...")
        elif choice == '2':
            print("🎯 选择: 执行应用程序")
            self._send_command('2')
            self.menu_detected = False
        elif choice == 'q':
            print("退出程序...")
            self.running = False
        else:
            print(f"❌ 无效选择: {choice}")
            self._show_input_prompt()
    
    def _send_command(self, command):
        """发送命令到MCU"""
        if self.ser and self.ser.is_open:
            # 发送命令 + 回车
            self.ser.write(f"{command}\r".encode())
            self.ser.flush()  # 确保命令发送完成
            print(f"📨 已发送命令: {command}")
    
    def close(self):
        """关闭连接"""
        self.running = False
        if self.ser and self.ser.is_open:
            self.ser.close()
            print("🔒 串口连接已关闭")

def main():
    """主函数"""
    print("=" * 60)
    print("        CM32M4xxR Bootloader 通信工具 - 增强版")
    print("=" * 60)
    
    try:
        # 创建并启动管理器
        manager = BootloaderManager(port='COM3', baudrate=115200)
        manager.start()
    except Exception as e:
        print(f"❌ 程序运行出错: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()