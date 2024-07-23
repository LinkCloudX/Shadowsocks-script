README
===========================
#### 关于本脚本
* 系统支持：CentOS 6+，Debian 7+，Ubuntu 12+
* 内存要求：≥128M
* 更新日期：2019 年 01 月 11 日
* 一键安装 `Shadowsocks-Python`， `Shadowsocks-Go`， `Shadowsocks-libev` 版（三选一）服务端；
* 各版本的启动脚本及配置文件名不再重合；
* 每次运行可安装一种版本；
* 支持以多次运行来安装多个版本，且各个版本可以共存（``` 注意端口号需设成不同```）；
* 若已安装多个版本，则卸载时也需多次运行（每次卸载一种）；

#### 默认配置
* 服务器端口：自己设定（如不设定，默认从 9000-19999 之间随机生成）
* 密码：自己设定（如不设定，默认为 `123456`）
* 加密方式：自己设定（如不设定，Python 和 libev 版默认为 `aes-256-gcm`，Go 版默认为 `aes-256-cfb`）
* 备注：脚本默认创建单用户配置文件，如需配置多用户，请手动修改相应的配置文件后重启即可。

#### 客户端下载
Windows 客户端
[https://github.com/2dust/v2rayN/releases]
Android 客户端
[https://github.com/2dust/v2rayNG/releases]

#### 使用方法
使用root用户登录，运行以下命令：

```bash
bash <(curl -s -L https://raw.githubusercontent.com/LinkCloudX/Shadowsocks-script/master/src/shadowscoks-all.sh)
```
如果出现`curl: command not found`字样，请安装`curl`。    
依据系统版本先运行：    
`apt-get install curl`或`yum install curl`     
然后再运行上面的命令。    

安装过程大约需要10分钟，具体时间依据服务器的性能决定。
安装完成后，脚本提示如下
```bash
Congratulations, your_shadowsocks_version install completed!
Your Server IP        :your_server_ip
Your Server Port      :your_server_port
Your Password         :your_password
Your Encryption Method:your_encryption_method

Your QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)
ss://your_encryption_method:your_password@your_server_ip:your_server_port
Your QR Code has been saved as a PNG file path:your_path.png

Welcome to visit:https://www.8void.com
Enjoy it!
```

#### 卸载方法
若已安装多个版本，则卸载时也需多次运行（每次卸载一种）
使用root用户登录，运行以下命令：

```bash
bash <(curl -s -L https://git.io/fjjvb) uninstall
```

#### 启动脚本
启动脚本后面的参数含义，从左至右依次为：启动，停止，重启，查看状态。

* Shadowsocks-Python 版：
`/etc/init.d/shadowsocks-python start | stop | restart | status`


* Shadowsocks-Go 版：
`/etc/init.d/shadowsocks-go start | stop | restart | status`

* Shadowsocks-libev 版：
`/etc/init.d/shadowsocks-libev start | stop | restart | status`

#### 各版本默认配置文件
* Shadowsocks-Python 版：
`/etc/shadowsocks-python/config.json`

* Shadowsocks-Go 版：
`/etc/shadowsocks-go/config.json`

* Shadowsocks-libev 版：
`/etc/shadowsocks-libev/config.json`

#### 更新日志

* 安装时可选 16 种加密方式的其中之一（Python 和 libev 版）。如下所示：
```bash
aes-256-gcm
aes-192-gcm
aes-128-gcm
aes-256-ctr
aes-192-ctr
aes-128-ctr
aes-256-cfb
aes-192-cfb
aes-128-cfb
camellia-128-cfb
camellia-192-cfb
camellia-256-cfb
chacha20-ietf-poly1305
chacha20-ietf
chacha20
rc4-md5
```

* 安装时可选 9 种加密方式的其中之一（Go 版）。如下所示：
```bash
aes-256-cfb
aes-192-cfb
aes-128-cfb
aes-256-ctr
aes-192-ctr
aes-128-ctr
chacha20-ietf
chacha20
rc4-md5
```
