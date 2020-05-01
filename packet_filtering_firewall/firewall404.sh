# !/bin/sh
# Homework Number:  hw09
# Name: Shu Hwai Teoh
# ECN Login: teoh0
# Due Date: Thursday 4/02/2020 at 4:29PM

# iptables <-t tableName> <-A/I/D/R chainName> <-p protocalName> <-s ipAddr> <--sport portnumber> <-d ipAddr> <--dport portnumber> <-j action> 
# aws: !/bin/bash


# flush the previous rules by 'iptables -t filter F' and delete the
# previous chains by 'iptables -t filter -X'
# F: remove rules
# -X: remove chains
sudo iptables -t filter -F
sudo iptables -t filter -X

# change source IP address of all outgoing packets to my machine's IP address
# -A: append new rule
# POSTROUTING: change source address
# -j: when the condition is match jump to target
# MASQUERADE: target lets you give it an interface, 
#       and whatever address is on that interface is the address that is applied 
#       to all the outgoing packets.
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Block a list of specic IP addresses for all incoming connections.
sudo iptables -A INPUT -s 8.8.8.8 -j REJECT
sudo iptables -A INPUT -s 10.0.0.24 -j REJECT

# Block your computer from being pinged by all other hosts
# -p: designate the protocal name
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT

# Set up port-forwarding from an unused port (5000) of your choice to port 22
# enable port 5000 for incoming tcp packet
sudo iptables -A INPUT -p tcp --dport 5001 -j ACCEPT
# enable packet forwarding to port 22
sudo iptables -A FORWARD -p tcp --dport 22 -j ACCEPT
# forward packet from port 5000 to port 22
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 5001 -j REDIRECT --to-port 22

# Allow for SSH access (port 22) to your machine from only the engineering.purdue.edu domain.
sudo iptables -A INPUT -p tcp -s engineering.purdue.edu  --dport 22 -j ACCEPT
# sudo iptables -A INPUT -p tcp ! -s engineering.purdue.edu  --dport 22 -j REJECT

# allows only a single IP address in the internet to access your machine for the HTTP service.
# https://www.baidu.com/: 103.235.46.39
sudo iptables -A INPUT -p tcp -s 103.235.46.39  --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp ! -s 103.235.46.39  --dport 80 -j REJECT

# Permit Auth/Ident (port 113)
sudo iptables -A INPUT -p tcp --dport 113 -j ACCEPT




