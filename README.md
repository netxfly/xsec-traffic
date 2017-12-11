## 概述

xsec-traffic为一款轻量级的恶意流量分析程序，包括传感器sensor和服务端server 2个组件。

### sensor
sensor负责采集流量，然后发到server端，由server来检测是否为恶意流量。

1. sensor支持采集TCP和UDP的五元组信息
1. 支持采集http请求信息
1. 支持采集同一局域网中其他机器的以上信息

### Server

server端的功能为接收各sensor采集到的流程并判断是否为恶意流量，其中：

1. IP五元组信息是通过查询恶意IP库来判断的
1. http请求数据的检测还在开发中（暂时会把所有取到的请求信息保存起来，理论上可支持检测所有来自WEB端的攻击类型，如注入、xss等）

## 使用说明
### Server
server需要mongodb的支持，在启动前需要事先准备一个有读写权限的mongodb账户，然后修改当前目录下的配置文件conf/app.ini，样例如下：
```ini
HTTP_HOST = 108.61.223.105
HTTP_PORT = 4433

DEBUG_MODE = TRUE
SECRET_KEY = xsec_secret_key

[EVIL-IPS]
API_URL = "http://www.xsec.io:8000"

[database]
DB_TYPE = mongodb
DB_HOST = 127.0.0.1
DB_PORT = 27017
DB_USER = xsec-traffic
DB_PASS = 7160c452342340787fasdfa5b0a9fe0
DB_NAME = xsec-traffic
```

1. HTTP_HOST和HTTP_PORT表示server端监听的地址及端口
1. DEBUG_MODE表示以debug模式运行
1. SECRET_KEY为sensor与server通讯用的密钥
1. EVIL-IPS部分为恶意IP库的地址
1. database部分为mongodb的配置

启动命令如下：
```
root@xsec:/data/golang/src/xsec-traffic/server# ./server 
[0000]  INFO xsec traffic server: DB Type: mongodb, Connect err status: <nil>
NAME:
   xsec traffic server - xsec traffic server

USAGE:
   server [global options] command [command options] [arguments...]

VERSION:
   20171210

AUTHOR:
   netxfly <x@xsec.io>

COMMANDS:
     serve    startup xsec traffic server
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug, -d               debug mode
   --server value, -s value  http server address
   --port value, -p value    http port (default: 1024)
   --help, -h                show help
   --version, -v             print the version
root@xsec:/data/golang/src/xsec-traffic/server# ./server serve
[0000]  INFO xsec traffic server: DB Type: mongodb, Connect err status: <nil>
[0000]  INFO xsec traffic server: run server on 108.61.223.105:4433
```

1. serve参数表示直接启动server服务器。

### sensor
sensor端也支持配置，修改当前目前下的conf/app.ini即可，详细的配置项如下：

```ini
; Sensor global config
DEVICE_NAME = en0
DEBUG_MODE = true
FILTER_RULE = tcp udp

[server]
API_URL = http://108.61.223.105:4433
API_KEY = xsec_secret_key
```
1. DEVICE_NAME表示需要采集流量的网卡名
1. DEBUG_MODE为Debug模式，正式使用时可关掉
1. FILTER_RULE为流量抓取规则，与wireshark的规则一致

sensor的命令行如下：
```bash
$ ./xsec_sensor
[0000]  INFO xsec traffic sensor: Device name:[en0], ip addr:[192.168.31.204], Debug mode:[true]
NAME:
   xsec traffic sensor - xsec traffic sensor, Support normal and arp spoof modes

USAGE:
   xsec_sensor [global options] command [command options] [arguments...]

VERSION:
   20171210

AUTHOR(S):
   netxfly <x@xsec.io>

COMMANDS:
     start    startup xsec traffic sensor
     arp      startup arp spoof mode
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug, -d                debug mode
   --filter value, -f value   setting filters
   --length value, -l value   setting snapshot Length (default: 1024)
   --target value, -t value   target ip address
   --gateway value, -g value  gateway ip address
   --help, -h                 show help
   --version, -v              print the version

```
1. start 表示直接只采集本地的流量
1. arp模式为arpspoof模式，可以采集同一局域网下的其他机器的流量，详细的命令行如下：
```
sudo ./xsec_sensor arp -t 192.168.31.215 -g 192.168.31.1
```
在启动前需要安装libpcap库并将内核参数设为允许转发，以下为3种OS的安装、设置方法：
```
# OSX
sudo sysctl net.inet.ip.forwarding=1

# FreeBSD
sudo sysctl -w net.inet.ip.forwarding=1

# Linux
sudo sysctl -w net.ipv4.ip_forward=1

# Fedora
sudo dnf install -y libpcap-devel

# Debian/Ubuntu
sudo apt-get install -y libpcap-dev

# OSX
brew install libpcap

# FreeBSD
sudo pkg install libpcap
```
需要指定采集的目标与网关，其中采集的目标的语法与nmap的一致，支持以下几种写法：
```
10.0.0.1
10.0.0.0/24
10.0.0.*
10.0.0.1-10
10.0.0.1, 10.0.0.5-10, 192.168.1.*, 192.168.10.0/24
```

## 实战演练

1. 启动server端

![](https://docs.xsec.io/images/xsec_traffic/server_serve.png)

1. 以正常模式启动sensor端

![](https://docs.xsec.io/images/xsec_traffic/sersor_start.png)

启动后可以看到我本地电脑的有道云音乐正在对外发包。

1. 在小米路由器中查到我Mix2手机的IP地址如下：

![](https://docs.xsec.io/images/xsec_traffic/mix_ip.png)

1. 将我的Mix2手机手工加到恶意IP库中

![](https://docs.xsec.io/images/xsec_traffic/evil_ips.png)

1. 以Arp模式启动，用电脑采集同一lan下Mix2手机的流量

![](https://docs.xsec.io/images/xsec_traffic/sensor_arp.png)

1. 可以通过server的简易后台看到检测结果：

![](https://docs.xsec.io/images/xsec_traffic/ret_conn.png)

![](https://docs.xsec.io/images/xsec_traffic/ret_req.png)


## 参考资料
1. [https://github.com/google/gopacket/](https://github.com/google/gopacket/)
1. [https://github.com/malfunkt/arpfox](https://github.com/malfunkt/arpfox)
1. [http://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket](http://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket)
