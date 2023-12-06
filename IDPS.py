import multiprocessing, psutil, time, os
from scapy.all import *


def syn():
    SYN_PACKET_COUNT = {} #list of syn packets incoming with IP
    def syn_mitigation(packet):
        if packet.haslayer(TCP) and packet[TCP].flags & 2 and packet.haslayer(IP) and packet[IP].dport == 80:
            src_ip = packet[IP].src

            if src_ip not in SYN_PACKET_COUNT:
                SYN_PACKET_COUNT[src_ip] = 1
            else:
                SYN_PACKET_COUNT[src_ip] += 1
                if SYN_PACKET_COUNT[src_ip] > 5:
                    print(f"Blocking SYN request from {src_ip}")
                    return

        send(packet)
    sniff(filter="tcp port 80", prn=syn_mitigation)

def icmp():
    ICMP_PACKET_COUNT = {}
    def icmp_mitigation(packet):
        if packet.haslayer(ICMP):
            src_ip = packet[IP].src

            if src_ip not in ICMP_PACKET_COUNT:
                ICMP_PACKET_COUNT[src_ip] = 1
            else:
                ICMP_PACKET_COUNT[src_ip] += 1

                if ICMP_PACKET_COUNT[src_ip] > 5:
                    print(f"Dropping ICMP request from {src_ip}")
                    return
        send(packet)
    sniff(filter="icmp", prn=icmp_mitigation)

def firefox_mitigation():
    ffProc="firefox"
    threshold=55
    ff_counter=0
    kill_threshold=4

    while True:
        procList=psutil.process_iter()
        for proc in procList:
            try:
                if proc.name() == ffProc:
                    cpu_percent=proc.cpu_percent()
                    if cpu_percent >= threshold:
                        print(f"Firefox process with PID {proc.pid} is consuming {cpu_percent}% of CPU")
                        ff_counter+=1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        if ff_counter >= kill_threshold:
            #os.system("kill -9 $(ps -x | grep firefox | awk '{print $1}')")
            os.system("pkill firefox")
            print(f"{ff_counter} Firefox processes were consuming too much CPU and had to be killed.")
            ff_counter=0
        time.sleep(3)
        

p1 = multiprocessing.Process(target=syn)
p2 = multiprocessing.Process(target=icmp)
p3 = multiprocessing.Process(target=firefox_mitigation)

p1.start()
p2.start()
p3.start()

p1.join()
p2.join()
p3.join()
