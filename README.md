# DoS-DDoS-IDPS-Project
Class project detecting and mitigating 3 DoS/DDoS attacks
CSCE 3560.001 Group 8
Final project README


Attacks, mitigation, and detection are all done on an Ubuntu VM.


IDPS:
This IDPS Python script includes three functions: syn, icmp, firefox_mitigaiton. 
Each of which implements a different type of security measure. 
"syn" detects and blocks SYN requests to port 80 from an IP address if more than 
5 requests are received. "icmp" drops ICMP requests from an IP address if more than 
5 requests are received. "firefox_mitigation" monitors the CPU usage of Firefox processes 
and kills them if they exceed a certain threshold. The script runs using the multiprocessing 
module to allow for parallel execution of the three functions.

Dependencies:
	Firewall must be enabled in order to open a port to attack with SYN flood,
	although it has no configurations to affect our attacks.

	sudo ufw enable
	sudo iptables -A INPUT -p tcp ---dport <port-number> -j ACCEPT


	To run the IDPS tool on ubuntu, <scapy.all import *> or <psutil> 
	imports won't run without without the following dependencies.

	sudo apt-get install python3-scapy 
	sudo apt install python3-pip
	pip install psutil


	Netplan configurations:
	
	In order to have different IPs on your VMs the following netplan configurations
	must be made on both VMs.
	
	sudo vim /etc/netplan/01-network-manager-all.yaml
	
	network:
	  version: 2
	  renderer: NetworkManager
	  ethernets:
	    enp0s3: 
	      dhep4: no 
	      addresses: [192.168.1.102/24]
	      routes:
		- to: 0.0.0.0/0
		  via: 192.168.1.1
	      nameservers:
		addresses: [8.8.8.8, 8.8.4.4]

	sudo netplan try (accept configurations by pressing enter)
	sudo netplan apply
	sudo reboot
				
	
Usage:

	sudo python3 IDPS.py
	

Attacks:

SYN Flood:
	This Python script attacks a specific IP and port by flooding the victim with a 
	given number of SYN packets.

Ping Flood:
	This Bash script uses ping command to ping a target IP address with a set amount 
	of pings, and a limiter to limit the number of pings send in an instance.

Firefox Browser Attack:
	This Bash script infinitely opens firefox windows and gives a 2 second sleep to give
	firefox a chance to process to operation. 


Dependencies:
	Firefox must be installed


	To run the SYN Flood on ubuntu, <scapy.all import *> import
	won't run without without the following dependencies.

	sudo apt-get install python3-scapy 

	
	Netplan configurations:
	
	In order to have different IPs on your VMs the following netplan configurations
	must be made on both VMs.
	
	sudo vim /etc/netplan/01-network-manager-all.yaml
	
	network:
	  version: 2
	  renderer: NetworkManager
	  ethernets:
	    enp0s3: 
	      dhep4: no 
	      addresses: [192.168.1.102/24]
	      routes:
		- to: 0.0.0.0/0
		  via: 192.168.1.1
	      nameservers:
		addresses: [8.8.8.8, 8.8.4.4]

	sudo netplan try (accept configurations by pressing enter)
	sudo netplan apply
	sudo reboot
	
Usage:
	synflood.py:
	
	sudo python3 synflood.py
	Enter attack IPdest
	Enter port dest
	Enter number of packets, 50-100 is recommended

	pingflood.sh:

	chmod +x pingflood.sh
	./pingflood.sh

	firefox_attack.sh:

	chmod +x firefox_attack.sh
	./firefox_attack
# CloudSecurity-IDPS-Project
