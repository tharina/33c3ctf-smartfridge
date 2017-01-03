#!/bin/bash

# Optional: flush existing rules
#sudo iptables -F
#sudo iptables -X

IFACE=eth0

SECONDS=60
BLOCKCOUNT=10
sudo iptables -A INPUT -p tcp --dport 12345 -i $IFACE -m state --state NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport 12345 -i $IFACE -m state --state NEW -m recent --update --seconds ${SECONDS} --hitcount ${BLOCKCOUNT} -j REJECT --reject-with tcp-reset
