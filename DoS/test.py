from TcpAttack import *
#Your TcpAttack class should be named as TcpAttack
spoofIP='8.8.8.19'
targetIP='146.112.62.105' #Will contain actual IP addresses in real script
rangeStart=20
rangeEnd=25
port=25
Tcp = TcpAttack(spoofIP,targetIP)
Tcp.scanTarget(rangeStart, rangeEnd)
if Tcp.attackTarget(port,5):
    print('port was open to attack')
