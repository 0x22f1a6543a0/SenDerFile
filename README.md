# SenDerFile 文件传送

## 开源协议 open-source license
> <font color='gree'>本程序参考并遵循GNU General Public License v3开源协议 \
> This program is used GNU General Public License v3 open-source license</font>

## 程序介绍 program introduction
> 1. <font color="cyan">本程序用来将文件发送给其他电脑（客户端） </br></br>
> 2. 相比于市面上存在的文件发送软件(software)，这个程序的优势在于不需要连接服务器；换句话说也就是没有大厂的登陆账号，校园网下不用互联网访问发送文件…… </br></br>
> 3. 部分现成软件没有的功能，如并发传输，自主选择传输协议，自拟报头格式，自定义加密算法/格式 </br></br>
> 4. 可拓展性，可维护性！</font>

## 程序使用 program used
> 编程语言：**<font color="cyan">Python</font>** \
> 库：<font color="cyan">Python标准发行版发行库</font>
> > 1. tkinter 界面库
> > 2. os 操作系统库
> > 3. time 时间库
> > 4. threading 多线程库
> > 5. socket 通信库
> > 6. hashlib hash混淆库
> > 7. string 字符串库
> > 8. random 随机库

## 程序支持 program supported
<font color="yellow">传输协议支持</font>
> - TCP (传输控制协议)
>   - 技术：STREAM
> - UDP (用户数据报协议)
>   - 技术：DGRAM

<font color="red">传输类型支持</font>
> - 本地
>   - localhost
> - 局域网
>   - lan
> - 公网（直接IP）
>   - public

<font color="gree">我们都有什么？</font>
> 1. 并发传输
> > 可以由一个服务端同时发送给多个客户端<font color="red">（高功耗）</font>
> 2. 迸发传输
> > 可以由一个服务器分别发送给多个客户端
> 3. 自主选择
> > - 用户自主选择使用什么协议
> 4. 安全性
> > - 程序没有对数据进行加密/泄露/上传别的服务器
> 5. 身份验证
> > - 可以对传输对象的身份进行验证，防止传输对象出错
> 6. hash验证
> > - 保证数据安全性

### <font color="red"> 开源精神 open-source mind
> 开源并不以为着免费拿给人去使用、修改 </br>
> 而是让更多技术大佬，社区贡献者一起维护代码！</font>