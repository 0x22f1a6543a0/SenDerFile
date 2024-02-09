# -*- coding: utf-8 -*-
"""
License: GNU General Public License v3
Source URL: https://github.com/0x22f1a6543a0/SenDerFile
"""
import hashlib
import os
import random
import string
import threading
import time
try:
    import tkinter as tk
    import tkinter.ttk as ttk
    import tkinter.filedialog as filedialog
    import tkinter.scrolledtext as Scrolledtext
    import tkinter.messagebox as msg

except ImportError:
    print("SenDerFile 错误： TKINTER无法导入\n"
          "如果您是Linux用户，则需要在中终端中输入：sudo apt-get install python-tk\n"
          "其他系统(Windows)建议重新安装Python3")
import socket

# 异步处理
import asyncio

# 系统库
import platform
import sys

# Bug 反馈需要的库
import smtplib
from email.mime.text import MIMEText
import re

# 查看更新的库
import urllib.request
import webbrowser

if "mac" in str(platform.system()).lower() or "dar" in str(platform.system()).lower():
    system = "mac"
elif "lin" in str(platform.system()).lower():
    system = "linux"
__version__ = "2.4.2"


# 查看更新
def update(return_=False):
    try:
        response = urllib.request.urlopen("https://0x22f1a6543a0.github.io/senderfile-api.html")
    except Exception as e:
        if return_:
            msg.showwarning("不可用", f"检查更新不可用\n原因：{e}")
        return
    newest_version = str(
        response.read().decode("utf-8")
    ).replace('\n', '').replace(' ', '')
    if system == "linux":
        url = "https://wwt.lanzouq.com/b0439ijwb"
        pwd = "dyu7"
    elif system == "mac":
        url = "未收录MacOS"
        pwd = "未收录MacOS"
    else:
        url = "https://wwvk.lanzouq.com/b043846zg"
        pwd = "cuv4"
    if newest_version != __version__:
        if (int(newest_version.replace(".", '')) >
                int(__version__.replace(".", ""))):
            if msg.askyesno("提示", f"您当前不是最新版！"
                                    f"\n最新版："+newest_version+f" |  您当前为：{__version__}\n"
                                    f"是否下载最新版？\n\n"
                                    f"下载地址：{url}\n"
                                    f"访问密码：{pwd}\n\n"
                                    f"按下“是”将会自动跳转网页和复制密码"):
                webbrowser.open(url)
                senderfile.clipboard_clear()
                senderfile.clipboard_append(pwd)
        else:
            msg.showwarning("嗯？", f"你确定你的版本是{__version__}？\n"
                                   f"怎么比匹配的最大版本{newest_version}还大？")
    else:
        if return_:
            msg.showinfo("恭喜", "你的SenDerFile客户端为最新版！")


def e():
    senderfile.notice_text.config(state=tk.NORMAL)
    try:
        notice = urllib.request.urlopen("https://0x22f1a6543a0.github.io/senderfile-notice.html")
    except Exception as e:
        senderfile.notice_text.delete(1.0, tk.END)
        senderfile.notice_text.config(fg='red')
        senderfile.notice_text.insert(tk.END, f"公告不可用！原因：{e}")
        senderfile.notice_text.config(state=tk.DISABLED)
        return
    senderfile.notice_text.config(fg="green", font=("楷体", 10, "bold"))
    senderfile.notice_text.delete(1.0, tk.END)
    senderfile.notice_text.insert(tk.END, notice.read().decode("utf-8"))
    senderfile.notice_text.config(state=tk.DISABLED)


threading.Thread(target=update).start()

booker = """
(中文版本)
零. SenDerFile为程序(Program)，不是软件(Software)

一. 安全问题/免责声明

1、 用户名为您的主机名
2、 hash校验算法为hashlib (Python™)提供
3、 在使用程序中的过程中如有发生信息泄露/黑客利用漏洞侵入个人计算机等事故由自己承担，不由开发者承担
4、 更新检查服务器均来自：https://github.com

二. 程序收集个人隐私

1、 本程序纯绿色，不存在收集隐私的行为
2、 本程序不会访问/监听/窃取任何一个其他软件上交服务器
3、 本程序不会监听任何硬件上交服务器！
4、 本程序不会有中转服务器存在。SenDerFile为半离线程序
5、 本程序会有网络监听，任何网络监听行为均为正常且合理

三. 程序信息

1、 本程序使用GNU General Public License v3开源协议，请遵守开源协议要求
2、 本程序开源地址：https://github.com/0x22f1a6543a0/SenDerFile


(English Version; Translation by Microsoft Bing)
ZERO. SenDerFile is a program, not Software

FIRST. Security Issues/Disclaimers

1. The username is your hostname
2. The hash verification algorithm is provided for hashlib (Python™).
3. In the process of using the program, if there is any information leakage/hacker exploiting vulnerabilities to invade the personal computer, etc., FOR IT BY YOURSELF, NOT FOR THE DEVELOPER
4. Check update server is from https://github.com

SECOND. The Program collects personal privacy
1. This program is pure green, and there is no collection of privacy
2. This program will not access/listen/steal any other software submitted to the server
3. This program will not listen to any hardware submitted to the server!
4. There will be no intermediary server in this program. SenDerFile is an offline program
5. There will be network monitoring in this program, and any network monitoring behavior is normal and reasonable

THIRD. Procedural Information

1. This program uses the GNU General Public License v3 open source license, please abide by the requirements of the open source license
2. Open source address of this program: https://github.com/0x22f1a6543a0/SenDerFile
"""


class ToolTip(tk.Toplevel):
    """
    一个气泡窗的方法
    """
    def __init__(self, wdgt, msg=None, msgFunc=None, delay: float = 1.0, follow=True):
        self.wdgt = wdgt
        self.parent = self.wdgt.master
        tk.Toplevel.__init__(self, self.parent, bg='black', padx=1, pady=1)
        self.withdraw()
        try:
            self.overrideredirect(True)
        except:
            pass
        self.msgVar = tk.StringVar()
        if msg is None:
            self.msgVar.set('No message provided')
        else:
            self.msgVar.set(msg)
        self.msgFunc = msgFunc
        self.delay = delay
        self.follow = follow
        self.visible = 0
        self.lastMotion = 0
        tk.Message(self, textvariable=self.msgVar, bg='#FFFFDD',
                aspect=1000).grid()
        self.wdgt.bind('<Enter>', self.spawn,
                       '+')
        self.wdgt.bind('<Leave>', self.hide, '+')
        self.wdgt.bind('<Motion>', self.move, '+')

    def spawn(self, event=None):
        self.visible = 1
        self.after(int(self.delay * 1000), self.show)

    def show(self):
        if self.visible == 1 and time.time() - self.lastMotion > self.delay:
            self.visible = 2
        if self.visible == 2:
            self.deiconify()

    def move(self, event):
        self.lastMotion = time.time()
        if not self.follow:
            self.withdraw()
            self.visible = 1
        self.geometry('+%i+%i' % (
        event.x_root + 10, event.y_root + 10))
        try:
            self.msgVar.set(
                self.msgFunc())
        except:
            pass
        self.after(int(self.delay * 1000), self.show)

    def hide(self, event=None):
        self.visible = 0
        self.withdraw()


class server:
    def send(self, path, progressbar, broker, port, type_="normal"):
        # UDP初始化
        if senderfile.license_radio.get() == 'udp':
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if senderfile.scanning_radio.get() and broker.get() != "LAN":
            msg.showwarning('哎呀', "身份验证只支持局域网模式，不支持其他模式")
            return
        if broker.get() == "LAN":
            ip = senderfile.lan_entry.get()
        elif broker.get() == "LOCALHOST":
            ip = senderfile.localhost_entry.get()
        else:
            ip = senderfile.public_entry.get()
        if type_ == "send":
            ip = senderfile.ver_user_entry.get().split(";")[0].replace("'", "")
            ip = ip.replace(")", "").replace("(", "")
            client_addresses = [(str(ip.split(",")[0]), int(ip.split(",")[-1]))]
        else:
            client_addresses = []
            # 传输初始化
            port = port.split(";")
            for p in port:
                try:
                    int(p)
                except:
                    msg.showwarning("嗯？", f"{p}不是纯数字，有内鬼终止交易")
                    return None
            # 判断是什么类型
            if broker.get() == "LAN":
                if senderfile.license_radio.get() == "udp":
                    if not senderfile.scanning_radio.get():
                        msg.showinfo("哎嘿", f"你选择是局域网传输模式，"
                            f"在该模式下需要先进行地址查询；该行为需要消耗最大{float(senderfile.timeout_entry.get())*255/60 + 1}分钟")
                    for p in port:
                        for i in range(255):
                            client_addresses.append((ip.replace("*", str(i)), int(p)))
                else:
                    msg.showwarning("警告", "你选择的是TCP传输协议，该协议无法启用局域网传输，请使用直接IP访问！")
                    return
            elif broker.get() == "LOCAL":
                client_addresses = [("127.0.0.1", int(port))]
            else:
                for p in port:
                    client_addresses.append((ip, int(p)))

        def sendto(client_addresses, progressbar, path, server, type_):
            asyncio.set_event_loop(asyncio.new_event_loop())
            loop = asyncio.get_event_loop()
            check_task = loop.create_task(check(progressbar, client_addresses, server, type_))
            loop.run_until_complete(check_task)
            loop.close()
            index = check_task.result()
            if index == -1:
                return None
            if not senderfile.scanning_radio.get() or type_ == "send":
                # 地址初始化
                server.settimeout(30)
                addr = client_addresses
                if type_ == "normal":
                    if broker.get() == "LAN":
                        addr = []
                        for i in range(len(port)):
                            addr.append(client_addresses[255 * i + index])
                if senderfile.license_radio.get() == "tcp":
                    if len(addr) >= 2:
                        msg.showerror("错误", "TCP协议不支持多地址传输，请使用UDP")
                    else:
                        server.connect(client_addresses[index])
                start = time.time()
                # 校验数据
                if senderfile.verify_radio.get():
                    mode = senderfile.verify_license.get()
                    if mode == "sha256":
                        func = hashlib.sha256
                    elif mode == "sha1":
                        func = hashlib.sha1
                    elif mode == "sha384":
                        func = hashlib.sha384
                    elif mode == "sha512":
                        func = hashlib.sha512
                    elif mode == "sha224":
                        func = hashlib.sha224
                    else:
                        func = hashlib.md5
                    if senderfile.license_radio.get() == "tcp":
                        server.send(f""
                                    f"{mode}:"
                                    f"{func(str(open(path, 'rb').read()).encode('utf-8')).hexdigest()}".encode("utf-8"))
                    else:
                        for client_address in addr:
                            server.sendto(f""
                                        f"{mode}:"
                                        f"{func(str(open(path, 'rb').read()).encode('utf-8')).hexdigest()}".encode("utf-8"), client_address)
                for client_address in addr:
                    # 文件变量
                    try:
                        f = open(path, 'rb')
                    except FileNotFoundError:
                        msg.showwarning("哎呀", f"没有在{path}下发现文件请重新填写文件")
                        return None
                    size = os.stat(path).st_size
                    # 文件初始化
                    filepath, shortname, extension = function.get_file(path)
                    data = bytes(str(shortname) + str(extension), encoding="utf-8")
                    if senderfile.license_radio.get() == "udp":
                        server.sendto(data, client_address)
                    else:
                        server.send(data)
                    # 其他初始化
                    progressbar['value'] = 0
                    progressbar['maximum'] = size
                    senderfile.progress.place(x=40, y=80)
                    while True:
                        # 读取文件往后拨56320位
                        data = f.read(56320)
                        if str(data) != "b''":
                            if senderfile.license_radio.get() == "udp":
                                server.sendto(data, client_address)
                            else:
                                server.send(data)
                        else:
                            if senderfile.license_radio.get() == "udp":
                                server.sendto("end".encode("utf-8"), client_address)
                            else:
                                server.send(data)
                            break
                        try:
                            accepted = server.recvfrom(56320)[0].decode()
                        except:
                            msg.showerror("哎呀",
                                          f"SDF好像在{client_address}迷路了，\n请你重新检查一下门牌号~")
                            return None
                        progressbar['value'] = int(accepted)
                        senderfile.progress.config(
                            text=f"已经发送{accepted}"
                            f"字节给{client_address}，完成进度：{addr.index(client_address) + 1}/{len(addr)}\n传输过程中不要更改任何设置！！！")

                server.close()
                progressbar['value'] = os.stat(path).st_size
                msg.showinfo("完成", f"您的传输已经完成啦！\n感谢您使用SDF文件传输！\n本次传输用时：{time.time()-start}s")
                senderfile.progress.config(text=f"发送完成，消耗{str(time.time()-start)[:4]}")
            return True
        if senderfile.duo_radio.get():
            if senderfile.broker_radio.get() != "LAN":
                for addr in client_addresses:
                    threading.Thread(target=sendto, args=([addr], progressbar, path, server, type_)).start()
            else:
                msg.showerror("错误", "SDF不支持局域网ip模式下的并发传输")
                return None
        else:
            threading.Thread(target=sendto, args=(client_addresses, progressbar, path, server, type_)).start()


class client:
    @staticmethod
    def listen():
        def listen():
            ver = value = verify = False
            if senderfile.license_radio.get() == 'udp':
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2**20-1)
            try:
                listen_address = (senderfile.listen_ip_entry.get(), int(senderfile.listen_port_entry.get()))
            except:
                msg.showerror("错误", "你输入的端口不是纯数字\n有内鬼，终止交易")
                return None
            try:
                client.bind(listen_address)
            except OSError:
                senderfile.log_text.insert(tk.END, f"[WARNING] {listen_address}已经被使用或不是一个正确的地址\n", "warning")
                return
            senderfile.log_text.insert(tk.END, f"[LISTENING] 开始监听， {listen_address}, 协议{senderfile.license_radio.get()}\n", "working")
            if senderfile.license_radio.get() == "tcp":
                client.listen(5)
                client, addr = client.accept()
            # 获取文件名
            if senderfile.license_radio.get() == "udp":
                filename, server_address = client.recvfrom(56320)
            else:
                filename = client.recv(56320)
                server_address = listen_address

            if filename.decode() == "AliveAndScan":
                senderfile.log_text.insert(tk.END, f"[DATA] 收到服务端的扫描请求，"
                                f"请求处理：{senderfile.username_entry.get()}\n", "data")
                client.sendto(f"{senderfile.username_entry.get()}".encode("utf-8"), server_address)
                if senderfile.license_radio.get() == "udp":
                    filename = client.recvfrom(56320)[0]
                else:
                    filename = client.recv(56320)

            if filename.decode() != "IsAlive":
                if "sha" in str(filename.decode())[:7] or "md" in str(filename.decode())[:4]:
                    senderfile.log_text.insert(tk.END, "[HASH] 服务端的信息中包含hash混淆！\n", "hash")
                    ver = True
                    verify = str(filename.decode()).split(":")[0]
                    value = str(filename.decode()).split(":")[-1]
                    filename = client.recvfrom(56320)[0]
                    f = open(filename, 'wb')
                else:
                    f = open(filename, 'wb')

            else:
                senderfile.log_text.insert(tk.END, "[DATA] 收到服务端的存活请求，请求处理：alive\n", "data")
                if senderfile.license_radio.get() == "udp":
                    client.sendto("alive".encode("utf-8"), server_address)
                else:
                    client.send("alive".encode("utf-8"))
                filename = client.recvfrom(56320)[0]
                f = open(filename, 'wb')
            # 初始化
            start = time.time()
            count = 0
            while True:
                try:
                    if senderfile.license_radio.get() == "udp":
                        data, server_address = client.recvfrom(56320)
                    else:
                        data = client.recv(56320)
                    if str(data) != "b'end'":
                        f.write(data)
                    else:
                        break
                    count += 1
                    if senderfile.license_radio.get() == "udp":
                        client.sendto(str(count * 56320).encode("utf-8"), server_address)
                    else:
                        client.send(str(count * 56320).encode("utf-8"))
                    senderfile.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}]  "
                                f"从：{server_address[0]}接收了{count * 56320}字节"
                                f"， 耗时：{str(time.time()-start)[:4]}\n", "sending")

                except:
                    break
                senderfile.log_text.yview_moveto(True)
                senderfile.log_text.update()
            senderfile.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] 完成接收！总共耗时：{time.time()-start}\n", "finish")
            senderfile.log_text.yview_moveto(True)
            senderfile.log_text.update()
            client.close()
            f.close()
            if ver:
                vf = open(filename, 'rb')
                data = open(filename, 'rb').read()
                if verify == "sha256":
                    now_value = hashlib.sha256(str(vf.read()).encode("utf-8")).hexdigest()
                elif verify == "sha1":
                    now_value = hashlib.sha1(str(vf.read()).encode("utf-8")).hexdigest()
                elif verify == "sha512":
                    now_value = hashlib.sha512(str(vf.read()).encode("utf-8")).hexdigest()
                elif verify == "sha224":
                    now_value = hashlib.sha224(str(vf.read()).encode("utf-8")).hexdigest()
                elif verify == "sha384":
                    now_value = hashlib.sha384(str(vf.read()).encode("utf-8")).hexdigest()
                else:
                    now_value = hashlib.md5(str(vf.read()).encode("utf-8")).hexdigest()
                vf.close()
                if now_value == value:
                    senderfile.log_text.insert(tk.END, f"[verify] 校验{verify}成功\n原hash值：{value}\n当前hash值：{now_value}\n", "finish")
                else:
                    os.remove(filename.decode("utf-8"))
                    senderfile.log_text.insert(tk.END, f"[verify] 校验{verify}失败\n原hash值：{value}\n当前hash值：{now_value}\n", "error")
                    if msg.askyesno("Hash错误", f"校验的Hash值和接受Hash值不同！hash算法：{verify}\n"
                                                f"校验hash: {value}\n"
                                                f"接收hash：{now_value}\n"
                                                f"请问是否继续？是：不进行操作，否：删除文件"):
                        open(filename, 'wb').write(data)
                senderfile.log_text.yview_moveto(True)
                senderfile.log_text.update()
            return None
        threading.Thread(target=listen).start()


class loggerOS:
    def __init__(self):
        senderfile.log_text.tag_configure("error", font=("宋体", 9, "bold"), foreground="red", background="black")
        senderfile.log_text.tag_configure("warning", font=("宋体", 10, "bold"), foreground="yellow")
        senderfile.log_text.tag_configure("finish", font=("楷体", 9, "bold"), foreground="green")
        senderfile.log_text.tag_configure("init", font=("华文楷体", 10), foreground="purple")
        senderfile.log_text.tag_configure("working", font=("楷体", 10, "bold"), foreground="blue")
        senderfile.log_text.tag_configure("sending", foreground="yellow")
        senderfile.log_text.tag_configure("data", foreground="pink", font=("华文楷体", 12))
        senderfile.log_text.tag_configure("hash", foreground="black")


async def check(progressbar, address, socket_, type_="normal"):
    index = -1
    if senderfile.scanning_radio.get():
        senderfile.account_listbox.delete(0, tk.END)
    progressbar['maximum'] = len(address)
    senderfile.progress.place(x=450, y=80)
    if len(address) > 1:
        for i in range(len(address) - 1):
            try:
                socket_.settimeout(float(senderfile.timeout_entry.get()))
            except:
                msg.showerror("嗯？", "你输入的超时时间不正确，\n有内鬼！终止交易！")
                return None
            try:
                senderfile.progress.place(x=100, y=80)
                senderfile.progress.config(
                    text=f"正在尝试{address[i]}，进度："
                    f"{address.index(address[i])}/{len(address) * len(senderfile.port_entry.get().split(';'))}"
                )
                progressbar['value'] = i
                if not senderfile.scanning_radio.get():
                    socket_.sendto("IsAlive".encode("utf-8"), address[i])
                else:
                    socket_.sendto("AliveAndScan".encode("utf-8"), address[i])
                r = str(socket_.recvfrom(1024)[0].decode())
                if r:
                    senderfile.public_entry.delete(0, tk.END)
                    senderfile.public_entry.insert(0, address[i][0])
                    index = i
                    if not senderfile.scanning_radio.get() or type_ == "send":
                        break
                    else:
                        senderfile.account_listbox.insert(tk.END, f"{address[i]} - {r}")
            except:
                pass
        else:
            if not senderfile.scanning_radio.get() or type_ == "send":
                msg.showwarning("哎呀", "没有找到任何一个发布在你提供的地址上的IP")
            else:
                msg.showinfo("完成", "扫描完成，所有存在的IP均在列表框中")
    if not senderfile.scanning_radio.get() or type_ == "send":
        progressbar['value'] = len(address)
    else:
        progressbar['value'] = 0
        senderfile.progress.config(text=f"检索完成")
    return index


class function:
    @staticmethod
    def get_file(path):
        filepath, tempfilename = os.path.split(path)
        shotname, extension = os.path.splitext(tempfilename)
        return [filepath, shotname, extension]

    @staticmethod
    def select_file(entry):
        entry.delete(0, tk.END)
        entry.insert(0, str(filedialog.askopenfilename()))

    @staticmethod
    def save_as():
        ask = filedialog.asksaveasfilename(title='另存日志……',
                                           initialdir=os.getcwd(),
                                           initialfile='log.log',
                                           filetypes=[("日志文件", ".log")])
        try:
            with open(ask, "w+", encoding="utf-8") as f:
                f.write(senderfile.log_text.get(1.0, tk.END))
            f.close()
        except:
            msg.showerror("噗", "SDF好像被某种东方的神秘力量拦截了……?")


class emali_send:
    def send(self):
        def sendtoemail():
            senderfile.progressbar_bug['value'] = 0
            r = random.randint(50, 79)
            from_message = senderfile.bug_text.get(0.0, tk.END)
            from_email = senderfile.from_email_entry.get()
            from_name = senderfile.from_bug_entry.get()
            if not str(from_message.strip()).replace(" ", ""):
                msg.showerror("错误", "BUG反馈内容不可为空！")
                return None
            else:
                if len(from_message) <= 10:
                    msg.showwarning("警告", "bug反馈的内容长度小于10")
                    return None
            if from_email.strip() == "":
                msg.showwarning("提示", "邮箱为必填项哦~")
                return
            else:
                regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
                if not re.fullmatch(regex, from_email):
                    msg.showerror("错误", "邮箱格式不正确！")
                    return
            for i in range(r):
                senderfile.progressbar_bug['value'] = i
                time.sleep(0.03)
            try:
                server = smtplib.SMTP_SSL("", )
                server.login("", "")
                # 发送感谢邮件
                thanks_message = f"""
                恭喜您成为 <SenDerFile> 贡献者之一！
                我们会尽快修复您描述的bug~
                {'-'*60}
                {from_message}
                {'-'*60}
                感谢您的bug反馈
                                             ——SenDerFile开发者
                """
                machine_thanks = MIMEText(thanks_message, "plain", "utf-8")
                machine_thanks['Subject'] = "SenDerFile 开发者感谢邮件"
                machine_thanks['From'] = ""
                machine_thanks["To"] = ','.join([f"{from_email}"])
                server.sendmail("",
                                f"{from_email}",
                                machine_thanks.as_string())

                # 发送邮件BUG
                message = f"""
                一封bug反馈邮件，内容：
                {'-'*60}
                {from_message}
                {'-'*60}
                反馈者签名：{from_name if from_name.strip() != "" else "是一位做好事不留名的好人呀~"}
                """
                machine_bug = MIMEText(message, "plain", "utf-8")
                machine_bug['Subject'] = "SenDerFile接受到一个bug反馈"
                machine_bug['From'] = ""
                machine_bug["To"] = ','.join([""])
                server.sendmail("",
                                "",
                                machine_bug.as_string())
                server.quit()
                for i in range(101 - r):
                    senderfile.progressbar_bug['value'] += 1
                    time.sleep(0.04)
                msg.showinfo('发送完成', "您的bug反馈邮件已经发送到开发者的邮箱中！\n"
                                         f"已经有一封感谢信发送到{from_email}中，谢谢您的bug反馈和支持！")

            except smtplib.SMTPException as e:
                msg.showerror("发送失败", "您的bug反馈邮件没有发送到开发者的邮箱中，\n"
                                          "原因：\n"
                                          f"{e}")
            senderfile.progressbar_bug['value'] = 0

        threading.Thread(target=sendtoemail).start()


class senderfile(tk.Tk):
    def __init__(self):
        super().__init__()
        self.notebook_count = 0
        self.function = function()
        self.ip = socket.gethostbyname(socket.gethostname())
        self.tk.call('tk', 'scaling', 1.3)
        self.geometry("700x550+300+100")
        self.title(f"SenDerFile -V {__version__} -F {os.getcwd()}")

        # 选项卡
        self.notebook = ttk.Notebook(self)
        self.send_frame = tk.Frame(self.notebook)
        self.accept_frame = tk.Frame(self.notebook)
        self.prime_frame = tk.Frame(self.notebook)

        self.network_frame = tk.Frame(self.notebook)
        self.network_notebook = ttk.Notebook(self.network_frame)
        self.bugger_frame = tk.Frame(self.network_notebook)
        self.other_frame = tk.Frame(self.network_notebook)
        self.notebook.add(self.send_frame, text="发送")
        self.notebook.add(self.accept_frame, text="接受")
        self.notebook.add(self.prime_frame, text="验证")
        self.notebook.add(self.network_frame, text="网络相关")
        self.network_notebook.add(self.bugger_frame, text="Bug反馈")
        self.network_notebook.add(self.other_frame, text="其他")
        # 其他
        tk.Label(self.other_frame, text="公告：").pack()
        if system != "linux":
            self.notice_text = Scrolledtext.ScrolledText(self.other_frame, state=tk.DISABLED)
        else:
            self.notice_text = Scrolledtext.ScrolledText(self.other_frame, state=tk.DISABLED, height=15)
        self.notice_text.pack()
        tk.Button(
            self.other_frame,
            text="刷新告示",
            command=lambda: threading.Thread(target=e).start()
        ).place(x=600, y=400)
        tk.Button(
            self.other_frame,
            text="检查更新",
            command=lambda: threading.Thread(target=lambda: update(True)).start()
        ).place(x=600, y=450)
        # BUG反馈
        if system != "linux":
            self.bug_text = Scrolledtext.ScrolledText(self.bugger_frame, font=("楷体", 10, "bold"))
        else:
            self.bug_text = Scrolledtext.ScrolledText(self.bugger_frame, font=("楷体", 10, "bold"),
                height=15)
        self.bug_text.pack()
        tk.Label(self.bugger_frame, text="发送者(邮箱)：*", fg="red").place(x=100, y=320)
        self.from_email_entry = tk.Entry(self.bugger_frame, width=50)
        self.from_email_entry.place(x=190, y=320)
        tk.Label(self.bugger_frame, text="发送者(签名)：").place(x=100, y=350)
        self.from_bug_entry = tk.Entry(self.bugger_frame, width=50)
        self.from_bug_entry.place(x=190, y=350)
        tk.Button(
            self.bugger_frame,
            text="发送反馈",
            command=emali_send().send).place(x=600, y=400)
        self.progressbar_bug = ttk.Progressbar(self.bugger_frame, maximum=100, value=0, length=650)
        self.progressbar_bug.place(x=30, y=450)
        # 权限的UI
        self.agreed = Scrolledtext.ScrolledText(self.prime_frame, height=10)
        self.agreed.pack(fill=tk.BOTH)
        self.agreed.tag_configure("title", font=("微软雅黑", 15, "bold"))
        self.agreed.tag_configure("booker", font=("宋体", 10))
        self.agreed.insert(tk.END, "《SenDerFile用户知情书》\n", "title")
        self.agreed.insert(tk.END, booker, "booker")
        self.agreed.config(state=tk.DISABLED)
        self.gqsyh_label = tk.Label(self.prime_frame, text="正确用户校验特征识别代码设置", font=("微软雅黑", 20, "bold"))
        self.gqsyh_label.pack()
        ToolTip(self.gqsyh_label, msg="当接受到发送信息时的校验身份的工具\n"
                                      "主要用途是：\n"
                                      "1、在同频段下的IP扫描的身份验证，-\n"
                                      " 防止优先IP被访问；防止传输对象错误")
        # 用户名设置
        self.username_entry = tk.Entry(self.prime_frame, width=40, font=("微软雅黑", 9, "bold"))
        self.username_entry.insert(0, str(socket.gethostname()))
        if system != "linux":
            tk.Label(self.prime_frame, text="用户名*：", fg="orange").place(x=100, y=200)
            self.username_entry.place(x=170, y=200)
        else:
            tk.Label(self.prime_frame, text="用户名*：", fg="orange").place(x=100, y=250)
            self.username_entry.place(x=170, y=250)

        # 接受的UI
        # 日志栏
        if system != "linux":
            self.log_text = Scrolledtext.ScrolledText(self.accept_frame, width=95, height=30, bg="skyblue")
        else:
            self.log_text = Scrolledtext.ScrolledText(self.accept_frame, width=95, height=22, bg="skyblue")
        self.log_text.insert(1.0, "[START] 程序正常打开\n", "init")
        self.log_text.place(x=0, y=0)
        # IP
        tk.Label(self.accept_frame, text="地址：").place(x=5, y=400)
        self.listen_ip_entry = tk.Entry(self.accept_frame)
        self.listen_ip_entry.insert(1, self.ip)
        self.listen_ip_entry.place(x=50, y=400)
        # 端口
        tk.Label(self.accept_frame, text="端口：").place(x=5, y=450)
        self.listen_port_entry = tk.Entry(self.accept_frame)
        self.listen_port_entry.insert(1, "9999")
        self.listen_port_entry.place(x=50, y=450)
        # 按钮
        tk.Button(self.accept_frame, text="监听", fg='green', command=client().listen).place(x=640, y=480)
        tk.Button(self.accept_frame, text="清除日志", fg='orange',
                  command=lambda: self.log_text.delete(1.0, tk.END)).place(x=540, y=480)
        tk.Button(self.accept_frame, text="保存日志", fg='red', command=self.function.save_as).place(x=440, y=480)

        # 发送的板块
        self.broker_frame = tk.LabelFrame(self.send_frame, text="传输地址", width=300, height=200)
        self.broker_frame.place(x=5, y=5)
        self.file_frame = tk.LabelFrame(self.send_frame, text="文件", width=650, height=150)
        self.file_frame.place(x=5, y=215)
        self.license_frame = tk.LabelFrame(self.send_frame, text="传输协议", width=300, height=80)
        self.license_frame.place(x=355, y=5)
        self.setting_frame = tk.LabelFrame(self.send_frame, text="传输设置", width=300, height=120)
        self.setting_frame.place(x=355, y=85)
        self.scanning_frame = tk.LabelFrame(self.send_frame, text="身份验证设置", width=650, height=120)
        self.scanning_frame.place_forget()
        # 发送的UI
        # 选择器 -> 传输设置
        self.duo_radio = tk.BooleanVar()
        self.duo_radio.set(False)
        self.duo_label = tk.Label(self.setting_frame, text="并发传输（高功耗）")
        self.duo_label.place(x=10, y=5)
        ToolTip(self.duo_label, msg=f"在多端口传输下同时发给其它客户端的功能\n"
                                    f"此功能可以提高速度，但会增加功耗\n"
                                    f"只能在直接IP下使用，局域网IP暂不支持\n"
                                    f"只能在UDP协议下使用，TCP协议不支持")
        self.duo_yes_radio = tk.Radiobutton(self.setting_frame, text="开启", variable=self.duo_radio, value=True)
        self.duo_yes_radio.place(x=140, y=5)
        self.duo_no_radio = tk.Radiobutton(self.setting_frame, text="关闭", variable=self.duo_radio, value=False)
        self.duo_no_radio.place(x=200, y=5)

        self.verify_radio = tk.BooleanVar()
        self.verify_radio.set(False)
        self.verify_label = tk.Label(self.setting_frame, text="发送校验")
        self.verify_label.place(x=10, y=35)
        ToolTip(self.verify_label, msg="在发送完成后请求客户端校验数据是否为正常数据\n以防止黑客劫持篡改数据")
        self.verify_yes_radio = tk.Radiobutton(self.setting_frame, text="开启", variable=self.verify_radio, value=True)
        self.verify_yes_radio.place(x=70, y=35)
        self.verify_no_radio = tk.Radiobutton(self.setting_frame, text="关闭", variable=self.verify_radio, value=False)
        self.verify_no_radio.place(x=140, y=35)
        self.verify_license = ttk.Combobox(
            self.setting_frame,
            values=["sha1", "sha224", "sha256", "sha384", "sha512", "md5"],
            width=9,
            state=tk.DISABLED)
        self.verify_license.set("md5")
        self.verify_license.place(x=200, y=35)

        def change(event):
            self.verify_license.config(state=tk.NORMAL)
            self.verify_license.config(state="readonly")

        self.verify_yes_radio.bind("<Button-1>", change)
        self.verify_no_radio.bind("<Button-1>", lambda event: self.verify_license.config(state=tk.DISABLED))

        self.target = tk.Label(self.setting_frame, text="目标身份验证")
        self.target.place(x=10, y=65)
        ToolTip(self.target, msg="发送信息到目标的校验身份工具\n"
                                  "主要用途是：\n"
                                  "1、在同频段下的IP扫描的身份验证，-\n"
                                  " 防止优先IP被访问；防止传输对象错误")
        self.scanning_radio = tk.BooleanVar()
        self.scanning_radio.set(False)
        self.scanning_yes_radio = tk.Radiobutton(
            self.setting_frame,
            text="启用",
            variable=self.scanning_radio,
            value=True
        )
        self.scanning_yes_radio.place(x=90, y=65)
        self.scanning_no_radio = tk.Radiobutton(
            self.setting_frame,
            text="关闭",
            variable=self.scanning_radio,
            value=False
        )
        self.scanning_no_radio.place(x=160, y=65)
        self.scanning_yes_radio.bind("<Button-1>", lambda event: self.show_disappear("show"))
        self.scanning_no_radio.bind("<Button-1>", lambda event: self.show_disappear("disappear"))

        # 选择器 -> 传输协议
        self.license_radio = tk.StringVar()
        self.license_radio.set("udp")
        tk.Label(self.license_frame, text="传输协议：").place(x=10, y=20)
        self.udp_radio = tk.Radiobutton(self.license_frame, text="UDP协议", variable=self.license_radio, value="udp")
        self.udp_radio.place(x=100, y=20)
        self.tcp_radio = tk.Radiobutton(self.license_frame, text="TCP协议", variable=self.license_radio, value="tcp")
        self.tcp_radio.place(x=200, y=20)
        ToolTip(self.udp_radio, msg="优：速度快，无连接，实时性\n"
                                    "缺：不可靠，不稳定，资源小\n"
                                    "场景：传输视频、音频")
        ToolTip(self.tcp_radio, msg="优：有序，容错高，资源大\n"
                                    "缺：速度慢，消耗高，开销大\n"
                                    "场景：传输大文件")
        # 选择器 -> 传输地址
        self.broker_radio = tk.StringVar()
        self.broker_radio.set("LAN")
        self.port_label = tk.Label(self.broker_frame, text="端口(0~65535)")
        self.port_label.place(x=10, y=150)
        ToolTip(self.port_label, msg="设置监听端口\n"
                                     "‘;’表示多端口传输(该模式请查看并发传输说明)")
        self.port_entry = tk.Entry(self.broker_frame)
        self.port_entry.insert(1, "9999")
        self.port_entry.place(x=110, y=150)
        self.timeout_label = tk.Label(self.broker_frame, text="超时时间：")
        self.timeout_label.place(x=10, y=120)
        ToolTip(self.timeout_label, msg="在局域网IP查找模式下单次查找的等待响应时间")
        self.timeout_entry = tk.Entry(self.broker_frame)
        self.timeout_entry.insert(1, "0.7")
        self.timeout_entry.place(x=90, y=120)

        self.localhost_radio = tk.Radiobutton(self.broker_frame, text="本地IP：",
                                              variable=self.broker_radio, value="LOCAL")
        self.localhost_radio.place(x=10, y=10)
        self.lan_radio = tk.Radiobutton(self.broker_frame, text="局域网IP：",
                                        variable=self.broker_radio, value="LAN")
        self.lan_radio.place(x=10, y=45)
        self.public_radio = tk.Radiobutton(self.broker_frame, text="直接IP：",
                                           variable=self.broker_radio, value="PUBLIC")
        self.public_radio.place(x=10, y=80)

        if system != "linux":
            self.protocol("WM_DELETE_WINDOW", lambda: os.system(f"taskkill /F /PID {os.getpid()}"))
        else:
            self.protocol("WM_DELETE_WINDOW", lambda: os.system(f"kill {os.getpid()}"))
        # 输入框 -> 传输地址
        # 本地
        self.localhost_entry = tk.Entry(self.broker_frame)
        self.localhost_entry.insert(1, "127.0.0.1")
        self.localhost_entry['state'] = tk.DISABLED
        self.localhost_entry.place(x=90, y=13)
        # 局域网
        self.lan_entry = tk.Entry(self.broker_frame)
        ip = self.ip.split(".")
        ip[-1] = "*"
        ip = '.'.join(ip)
        self.lan_entry.insert(1, ip)
        self.lan_entry.place(x=100, y=48)
        ToolTip(self.lan_radio, msg="改模式下‘*’表示不确定的值，程序会启动IP查找")
        # 直接
        self.public_entry = tk.Entry(self.broker_frame)
        self.public_entry.insert(1, self.ip)
        self.public_entry.place(x=90, y=83)

        # 文件 -> 文件
        tk.Label(self.file_frame, text="进度").place(x=5, y=50)
        self.progressbar = ttk.Progressbar(self.file_frame, length=600, maximum=100, value=100, cursor="spider")
        self.progressbar.place(x=40, y=50)
        if system != "linux":
            self.filename_entry = tk.Entry(self.file_frame, width=65)
        else:
            self.filename_entry = tk.Entry(self.file_frame, width=55)
        self.filename_entry.place(x=100, y=0)
        tk.Label(self.file_frame, text="[*]文件目录：", fg="red").place(x=10, y=0)
        if system != "linux":
            tk.Button(self.file_frame, text="选择文件",
                    command=lambda: function.select_file(self.filename_entry)).place(x=580, y=0)
        else:
            tk.Button(self.file_frame, text="选择文件",
                    command=lambda: function.select_file(self.filename_entry)).place(x=560, y=0)
        self.send_button = tk.Button(self.file_frame, text="传输", fg="green",
                  command=lambda: server.send(self.filename_entry.get(),
                                              self.progressbar,
                                              self.broker_radio,
                                              self.port_entry.get(),
                                              "normal"))
        if system != "linux":
            self.send_button.place(x=600, y=90)
        else:
            self.send_button.place(x=590, y=90)

        # 其他
        self.progress = tk.Label(self.file_frame, text="未启动", justify=tk.LEFT)
        self.progress.place(x=500, y=80)
        # 身份验证容器
        tk.Label(self.scanning_frame, text="用户").place(x=10, y=10)
        self.ver_user_entry = tk.Entry(self.scanning_frame, width=40, state=tk.DISABLED)
        self.ver_user_entry.place(x=60, y=10)
        self.ver_send_button = tk.Button(
            self.scanning_frame,
            text="传输",
            state=tk.DISABLED,
            command=lambda: server.send(self.filename_entry.get(),
                                        self.progressbar,
                                        self.broker_radio,
                                        self.port_entry.get(),
                                        "send")
        )
        if system != "linux":
            self.ver_send_button.place(x=600, y=60)
        else:
            self.ver_send_button.place(x=590, y=60)
        # 加载身份验证器
        self.Scrollbar = ttk.Scrollbar(self.send_frame)
        if system != "linux":
            self.account_listbox = tk.Listbox(self.send_frame, width=43, height=25, yscrollcommand=self.Scrollbar.set)
        else:
            self.account_listbox = tk.Listbox(self.send_frame, width=38, height=20, yscrollcommand=self.Scrollbar.set)
        self.title_account_label = tk.Label(
            self.send_frame,
            text="查找到的身份列表",
            font=("微软雅黑", 15, "bold"))
        self.account_listbox.bind(
            "<<ListboxSelect>>",
            lambda event: self.finish_check()
        )
        self.log_text.insert(2.0, "[INIT] 初始化完成\n", "init")
        self.log_text.insert(3.0, f"{'-'*90}\n[LICENSE] GNU General Public License v3\n{'-'*90}\n", "init")

        # 绑定快捷键
        self.bind("<Control-Up>", self.key_up)
        self.bind("<Control-Down>", self.key_down)
        self.bind("<Control-Right>", self.key_left)
        self.bind("<Control-Left>", self.key_right)
        self.bind("<Control-u>", lambda event: self.license_radio.set("udp"))
        self.bind("<Control-t>", lambda event: self.license_radio.set("tcp"))
        self.bind("<Control-s>", lambda event: function.select_file(self.filename_entry))
        self.bind("<Control-l>", lambda event: client.listen())

        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.network_notebook.pack(fill=tk.BOTH, expand=True)

    def key_up(self, event):
        if self.broker_radio.get() == "LOCAL":
            self.broker_radio.set("PUBLIC")
        elif self.broker_radio.get() == "LAN":
            self.broker_radio.set("LOCAL")
        else:
            self.broker_radio.set("LAN")

    def key_down(self, event):
        if self.broker_radio.get() == "LOCAL":
            self.broker_radio.set("LAN")
        elif self.broker_radio.get() == "LAN":
            self.broker_radio.set("PUBLIC")
        else:
            self.broker_radio.set("LOCAL")

    def key_right(self, event):
        self.notebook_count -= 1
        if self.notebook_count < 0:
            self.notebook_count = 3
        self.notebook.select(self.notebook_count)

    def key_left(self, event):
        self.notebook_count += 1
        if self.notebook_count > 3:
            self.notebook_count = 0
        self.notebook.select(self.notebook_count)

    def finish_check(self):
        user = '-'.join(str(
            self.account_listbox.get(self.account_listbox.curselection())
        ).replace(" ", "").split("-")[1:])
        ip = ''.join(str(
            self.account_listbox.get(self.account_listbox.curselection())
        ).replace(" ", "").split("-")[0])
        self.ver_user_entry.config(state=tk.NORMAL)
        self.ver_user_entry.delete(0, tk.END)
        self.ver_user_entry.insert(0, f"{str(ip)};{str(user)}")
        self.ver_user_entry.config(state=tk.DISABLED)
        self.ver_send_button.config(state=tk.NORMAL)

    def show_disappear(self, type_):
        if type_ == "disappear":
            self.scanning_frame.place_forget()
            self.geometry("700x550")
            self.account_listbox.place_forget()
            self.title_account_label.place_forget()
            self.Scrollbar.pack_forget()
            self.send_button.config(text="传输")
        else:
            self.scanning_frame.place(x=5, y=375)
            self.geometry("1020x550")
            self.send_button.config(text="检索", command=lambda: server.send(self.filename_entry.get(),
                                              self.progressbar,
                                              self.broker_radio,
                                              self.port_entry.get(),
                                              "normal"),
                                    )
            self.account_listbox.place(x=670, y=50)
            self.title_account_label.place(x=750, y=0)
            self.Scrollbar.pack(fill=tk.BOTH, side=tk.RIGHT)


senderfile = senderfile()
loggerOS = loggerOS()
threading.Thread(target=e).start()

server = server()
client = client()
function = function()

if __name__ == '__main__':
    senderfile.mainloop()
