import socket
import sys
import threading
from collections import deque

class NoNewlineTerminal:
    def __init__(self, client_socket):
        self.client_socket = client_socket
        self.last_received = deque(maxlen=10)
        self.running = True
        self.prompt = ""
        self.current_input = ""

    def receive_handler(self):
        try:
            while self.running:
                data = self.client_socket.recv(4096)
                if not data:
                    print("\n[!] Connection closed by client")
                    self.running = False
                    break
                
                decoded = data.decode('utf-8', errors='replace')
                for line in decoded.splitlines():
                    if line.strip():
                        self.last_received.append(line)
                
                # 在接收消息时重新显示当前输入
                sys.stdout.write("\r" + " " * 100 + "\r")  # 清除当前行
                print(f"{decoded}", end='')
                sys.stdout.write(f"{self.prompt}{self.current_input}")
                sys.stdout.flush()
                
        except ConnectionResetError:
            print("\n[!] Client disconnected unexpectedly")
            self.running = False

    def display_last_message(self):
        if self.last_received:
            # 不换行，直接覆盖当前行显示最后消息
            sys.stdout.write("\r" + " " * 100 + "\r")  # 清除当前行
            print(f"{self.last_received[-1]}", end='')
            sys.stdout.write(f"{self.prompt}{self.current_input}")
            sys.stdout.flush()
        else:
            sys.stdout.write("\r" + " " * 100 + "\r")  # 清除当前行
            sys.stdout.write(f"{self.prompt}{self.current_input}")
            sys.stdout.flush()

    def start(self):
        recv_thread = threading.Thread(target=self.receive_handler)
        recv_thread.daemon = True
        recv_thread.start()

        print("\nInteractive Terminal (Press Enter to show last message)")
        while self.running:
            try:
                # 逐字符读取输入
                self.current_input = ""
                sys.stdout.write(self.prompt)
                sys.stdout.flush()
                
                while True:
                    char = sys.stdin.read(1)
                    
                    # 处理回车键
                    if char == '\n':
                        if not self.current_input.strip():
                            self.display_last_message()
                        else:
                            # 发送命令到客户端
                            self.client_socket.send((self.current_input + "\n").encode('utf-8'))
                            self.current_input = ""
                            sys.stdout.write(self.prompt)
                            sys.stdout.flush()
                        break
                    
                    # 处理退格键
                    elif char == '\x7f':
                        if len(self.current_input) > 0:
                            self.current_input = self.current_input[:-1]
                            sys.stdout.write("\b \b")  # 回退并清除字符
                            sys.stdout.flush()
                    
                    # 普通字符
                    else:
                        self.current_input += char
                        sys.stdout.write(char)
                        sys.stdout.flush()
                        
            except KeyboardInterrupt:
                print("\n[!] Use Ctrl+D to exit")
                continue
                
            except EOFError:
                print("\n[+] Exiting...")
                self.running = False
                break
                
        self.client_socket.close()

def netcat_listen(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(1)
        
        print(f"[*] Listening on 0.0.0.0:{port}")
        client_socket, addr = s.accept()
        print(f"[*] Connection from {addr[0]}:{addr[1]}")
        
        terminal = NoNewlineTerminal(client_socket)
        terminal.start()
        
        s.close()
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <port>")
        sys.exit(1)
    
    try:
        port = int(sys.argv[1])
        if not 0 < port <= 65535:
            raise ValueError
    except ValueError:
        print("Error: Port must be a number between 1 and 65535")
        sys.exit(1)
    
    netcat_listen(port)