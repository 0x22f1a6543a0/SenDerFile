# -*- coding: utf-8 -*-
"""
License: GNU General Public License v3
Source URL: https://github.com/0x22f1a6543a0/SenDerFile
"""
import os
import threading
import time
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.filedialog as filedialog
import tkinter.scrolledtext as Scrolledtext
import tkinter.messagebox as msg
import socket

License = """SenDerFile  Copyright (C) 2024  张嘉祺
This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
This is free software, and you are welcome to redistribute it
under certain conditions; type `show c' for details."""


class ToolTip(tk.Toplevel):
    """
    一个气泡窗的方法
    """
    def __init__(self, wdgt, msg=None, msgFunc=None, delay: float=1.0, follow=True):
        self.wdgt = wdgt
        self.parent = self.wdgt.master
        tk.Toplevel.__init__(self, self.parent, bg='black', padx=1, pady=1)
        self.withdraw()
        self.overrideredirect(True)

        self.msgVar = tk.StringVar()
        if msg == None:
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
        if self.follow == False:
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
    def __init__(self):
        self.duo = {}

    def send(self, path, progressbar, broker, port):
        # UDP初始化
        if senderfile.license_radio.get() == 'udp':
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if broker.get() == "LAN":
            ip = senderfile.lan_entry.get()
        elif broker.get() == "LOCALHOST":
            ip = senderfile.localhost_entry.get()
        else:
            ip = senderfile.public_entry.get()
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
        def sendto(client_addresses, progressbar, path, server):
            # 启动线程过一遍检查
            threading.Thread(target=lambda: function.check(progressbar, client_addresses, server)).start()
            # 等待检查结束（不开两个线程会导致未响应）
            while True:
                if function.ischeck:
                    break
            # 地址初始化
            server.settimeout(30)
            addr = client_addresses
            if broker.get() == "LAN":
                addr = []
                for i in range(len(port)):
                    addr.append(client_addresses[255 * i + function.index])
            if senderfile.license_radio.get() == "tcp":
                if len(addr) >= 2:
                        msg.showerror("错误", "TCP协议不支持多地址传输，请使用UDP")
                else:
                    server.connect(client_addresses[function.index])
            start = time.time()
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
                    senderfile.progress.config(text=f"已经发送{accepted}字节给{client_address}，完成进度：{addr.index(client_address) + 1}/{len(addr)}\n传输过程中不要更改任何设置！！！")

            server.close()
            progressbar['value'] = os.stat(path).st_size
            msg.showinfo("完成", f"您的传输已经完成啦！\n感谢您使用SDF文件传输！\n本次传输用时：{time.time()-start}s")
            senderfile.progress.config(text=f"发送完成，消耗{str(time.time()-start)[:4]}")
            return True
        if senderfile.duo_radio.get():
            if senderfile.broker_radio.get() != "LAN":
                for addr in client_addresses:
                    threading.Thread(target=lambda: sendto([addr], progressbar, path, server)).start()
            else:
                msg.showerror("错误", "SDF不支持局域网ip模式下的并发传输")
                return None
        else:
            threading.Thread(target=lambda: sendto(client_addresses, progressbar, path, server)).start()


class client:
    @staticmethod
    def listen():
        def listen():
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
            client.bind(listen_address)
            senderfile.log_text.insert(tk.END, f"[LISTENING] 开始监听， {listen_address}\n")
            senderfile.log_text.config(fg="purple")
            if senderfile.license_radio.get() == "tcp":
                client.listen(5)
                client, addr = client.accept()
            # 获取文件名
            if senderfile.license_radio.get() == "udp":
                filename, server_address = client.recvfrom(56320)
            else:
                filename = client.recv(56320)
                server_address = listen_address
            if filename.decode() != "IsAlive":
                f = open(filename, 'wb')
            else:
                if senderfile.license_radio.get() == "udp":
                    client.sendto("alive".encode("utf-8"), server_address)
                else:
                    client.send("alive".encode("utf-8"))
                filename = client.recvfrom(56320)[0]
                f = open(filename, 'wb')
            # 初始化
            start = time.time()
            count = 0
            senderfile.log_text.config(fg='orange')
            while True:
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
                senderfile.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}]  从：{server_address[0]}接收了{count * 56320}字节"
                                                   f"， 耗时：{str(time.time()-start)[:4]}\n")
                senderfile.log_text.yview_moveto(True)
                senderfile.log_text.update()
            senderfile.log_text.config(fg="green")
            senderfile.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] 完成接收！总共耗时：{time.time()-start}\n")
            senderfile.log_text.yview_moveto(True)
            senderfile.log_text.update()
            client.close()
            f.close()
            return None
        threading.Thread(target=listen).start()


class function:
    def __init__(self):
        self.index = 0
        self.ischeck = False

    def check(self, progressbar, address, socket_):
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
                    senderfile.progress.config(text=f"正在尝试{address[i]}")
                    progressbar['value'] = i
                    socket_.sendto("IsAlive".encode("utf-8"), address[i])
                    if str(socket_.recvfrom(1024)[0].decode()):
                        senderfile.public_entry.delete(0, tk.END)
                        senderfile.public_entry.insert(0, address[i][0])
                        self.index = i
                        break
                except:
                    pass
            else:
                msg.showwarning("哎呀", "没有找到任何一个发布在你提供的地址上的IP")
        progressbar['value'] = len(address)
        self.ischeck = True
        time.sleep(0.2)
        self.__init__()

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


class senderfile(tk.Tk):
    def __init__(self):
        super().__init__()
        self.function = function()
        self.ip = socket.gethostbyname(socket.gethostname())
        self.tk.call('tk', 'scaling', 1.3)
        self.geometry("700x550+300+100")
        self.title(f"SenDerFile -F {os.getcwd()}")

        # 选项卡
        self.notebook = ttk.Notebook(self)
        self.send_frame = tk.Frame(self.notebook)
        self.accept_frame = tk.Frame(self.notebook)
        self.notebook.add(self.send_frame, text="发送")
        self.notebook.add(self.accept_frame, text="接受")
        # 接受的UI
        # 日志栏
        self.log_text = Scrolledtext.ScrolledText(self.accept_frame, width=95, height=30, fg='red')
        self.log_text.insert(1.0, "[START] 程序正常打开\n")
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
        self.file_frame = tk.LabelFrame(self.send_frame, text="文件", width=650, height=250)
        self.file_frame.place(x=5, y=215)
        self.license_frame = tk.LabelFrame(self.send_frame, text="传输协议", width=300, height=80)
        self.license_frame.place(x=355, y=5)
        self.setting_frame = tk.LabelFrame(self.send_frame, text="传输设置", width=300, height=120)
        self.setting_frame.place(x=355, y=85)
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

        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.protocol("WM_DELETE_WINDOW", lambda: os.system(f"taskkill /F /PID {os.getpid()}"))
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
        self.progressbar = ttk.Progressbar(self.file_frame, length=600, maximum=100, value=100)
        self.progressbar.place(x=40, y=50)

        self.filename_entry = tk.Entry(self.file_frame, width=65)
        self.filename_entry.place(x=100, y=0)
        tk.Label(self.file_frame, text="[*]文件目录：", fg="red").place(x=10, y=0)
        tk.Button(self.file_frame, text="选择文件",
                  command=lambda: function.select_file(self.filename_entry)).place(x=580, y=0)
        tk.Button(self.file_frame, text="传输", fg="green",
                  command=lambda: server.send(self.filename_entry.get(),
                                              self.progressbar,
                                              self.broker_radio,
                                              self.port_entry.get())).place(x=600, y=190)

        # 其他
        self.progress = tk.Label(self.file_frame, text="未启动", justify=tk.LEFT)
        self.progress.place(x=500, y=80)

        self.log_text.insert(2.0, "[INIT] 初始化完成\n")
        self.log_text.insert(3.0, f"{'-'*90}\n[LICENSE] GNU General Public License v3\n\n{License}\n{'-'*90}\n")


senderfile = senderfile()
server = server()
client = client()
function = function()

if __name__ == '__main__':
    senderfile.mainloop()
