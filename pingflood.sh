#!/usr/bin/bash

ip_addr="192.168.1.101"
max_pings=100
ping_count=0

while [ $ping_count -lt $max_pings ]
do
	if ping -c 1 $ip_addr >/dev/null; then
		echo "Ping successful"
	else
		echo "Ping failed"
	fi
	ping_count=$((ping_count + 1))
done


