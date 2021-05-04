import netifaces
import sys
import binascii
from scapy.all import *
from time import sleep
from pyroute2 import IPRoute
from ipaddress import IPv4Network
from getmac import get_mac_address

dhcpserverip=""
offeredip=""
sub_mask=""
router_id=""

def handle_dhcp(packet):
    global dhcpserverip
    global offeredip
    global sub_mask
    global router_id

    for check in packet[DHCP].options:
        if check[0]=="message-type":
                
                if check[1]==2:
                
                        print ("[+] DHCP Offer received")
                        dhcpserverip=packet[IP].src
                        offeredip=packet[BOOTP].yiaddr
                
                        for options_attrib in packet[DHCP].options:
                            if options_attrib[0]=="subnet_mask":
                                 sub_mask=options_attrib[1]
                            if options_attrib[0]=="router":
                                 router_id=options_attrib[1]

        print ("[+] DHCP Server IP:",dhcpserverip)
        print ("[+] Offered IP:",offeredip)
        print ("[+] Subnet mask:",sub_mask)
        print ("[+] Gateway:",router_id)

        if check[1]==5:
                
                print ("[+] DHCP ACK received, IP allocation done")

                ip=IPRoute()
                index=ip.link_lookup(ifname='eth0')[0]

# Need to figure out how to assign broadcast address- not part of DHCP reponse
# Interface is assigned proper IP address

                mask_short=IPv4Network((0,sub_mask))
                mask_short=mask_short.prefixlen
                max_short=24
                print ("Mask=",mask_short)
                ip.addr('add',index,address=offeredip,mask=mask_short)
                ip.close()

def listen():
    print ("starting sniffer...")
    sniff(iface="eth0",filter="port 67 or port 68",prn=handle_dhcp)

# Main program

clientmac=get_mac_address(interface="eth0")

#clientmac="08:20:27:b1:aa:8c" some example MACs from my internal lab
#clientmac="ee:bf:a6:14:dc:e3"

clientmacraw=binascii.unhexlify(clientmac.replace(':',''))
host_name="BadHAcker"

if len(sys.argv)!=2:

        print ("Usage: python scapydhcpclient.py <profile>")
        print ("Profile can be any of:")
        print (" microsoft")
        print (" Linux")
        print (" CiscoAp")
        print (" HPLAsterJet")
        print (" minimal")
        sys.exit()

if sys.argv[1]=="microsoft":
    
        vendorid="MSFT 5.0"
        dhcp_options=[
            ("message-type","discover"),
            ("client_id",chr(1),clientmacraw),
            ("hostname",host_name),                     
            ("vendor_class_id", vendorid),
            ("param_req_list", [
                DHCPRevOptions["subnet_mask"][0],       # 1
                DHCPRevOptions["name_server"][0],       # 6
                DHCPRevOptions["router"][0],            # 3
                DHCPRevOptions["domain"][0],            # 15
                DHCPRevOptions["router-discovery"][0],   # 31
                DHCPRevOptions["static-routes"][0],      # 33
                DHCPRevOptions["vendor_specific"][0],       # 43
                DHCPRevOptions["NetBIOS_server"][0],    # 44
                46, 									# NEtBIOS-node-type
                DHCPRevOptions["netbios-scope"][0],     # 47
                DHCPRevOptions["domain"][0],            # 119
                DHCPRevOptions["static-routes"][0],     # 121
                249,                                    # Classless static routes (Microsoft)
                252,                                    # Private Proxy Autodiscovery
                ]),
                "end"
                ]

elif sys.argv[1]=="Linux":

        vendorid="Linux"
        dhcp_options=[
            ("message-type","discover"),
            ("hostname",host_name),
            ("param_req_list", [
                DHCPRevOptions["subnet_mask"][0],       # 1
                DHCPRevOptions["time_zone"][0],         # 2
                DHCPRevOptions["name_server"][0],       # 6
                DHCPRevOptions["router"][0],            # 3
                DHCPRevOptions["hostname"][0],          # 12
                DHCPRevOptions["domain"][0],            # 15
                DHCPRevOptions["interface-mtu"][0],     # 26
                DHCPRevOptions["broadcast_address"][0],  # 28
                DHCPRevOptions["time_server"][0],       # 42
                DHCPRevOptions["NetBIOS_server"][0],    # 44
                DHCPRevOptions["netbios-scope"][0],     # 47
                DHCPRevOptions["domain"][0],            # 119
                DHCPRevOptions["static-routes"][0],      # 121
                ]),
                "end"
                ]
elif sys.argv[1]=="CiscoAp":

        vendorid="Cisco AP 1500"
        dhcp_options=[
            ("message-type","discover"),
            ("hostname",host_name),
            ("param_req_list", [
                DHCPRevOptions["subnet_mask"][0],       # 1
                DHCPRevOptions["broadcast_address"][0],  # 28
                ]),
                "end"
                ]

elif sys.argv[1]=="HPLaserJet":

        vendorid="LaserJet"
        dhcp_options=[
            ("message-type","discover"),
            ("hostname",host_name),
            ("param_req_list", [
                DHCPRevOptions["subnet_mask"][0],       # 1
                DHCPRevOptions["broadcast_address"][0],  # 28
                ]),
                "end"
                ]

elif sys.argv[1]=="minimal":

        vendorid=""
        dhcp_options=[
            ("message-type","discover"),
            ("hostname",host_name),
            ("param_req_list", [
                DHCPRevOptions["subnet_mask"][0],       # 1
                DHCPRevOptions["broadcast_address"][0],  # 28
                ]),
                "end"
                ]

ether=Ether(dst="ff:ff:ff:ff:ff:ff",src=clientmac,type=0x0800)
ip=IP(src="0.0.0.0",dst="255.255.255.255")
udp=UDP (sport=68, dport=67)
bootp=BOOTP(ciaddr="0.0.0.0",chaddr=clientmacraw,xid=0x1020304,flags=1)

dhcp=DHCP(options=dhcp_options)

packet=  ether / ip / udp /bootp / dhcp

for ifaces in netifaces.interfaces():
    if ifaces=="eth0" :
            print (ifaces)

# IMPORTANT - you need to run separate thread with sniff(filter="udp and (port 67 or port 68)",prn=handle_dhcp)
# handle_dhcp is another callback function that parses dhcp reponse

            thread=Thread(target=listen)
            thread.start()

# Sleep below is important to allow sniffer to catch initial packets
            sleep(1)

            sendp(packet)
            print ("[+] Packet sent")

# Constructing DHCP Request message - ether , ip, bootp headers are the same
            sleep(1)

            dhcp_req_options=[
                ("message-type","request"),
                ("client_id",chr(1),clientmacraw),
                ("vendor_class_id",vendorid),
                ("hostname",host_name),
                ("requested_addr",offeredip),
                ("server_id",dhcpserverip),
                ("param_req_list", [
                    DHCPRevOptions["subnet_mask"][0],
                    DHCPRevOptions["router"][0],
                    DHCPRevOptions["name_server"][0],
                    DHCPRevOptions["broadcast_address"][0],
                    ]),
                  "end"]

            dhcp=DHCP(options=dhcp_req_options)
            packet=ether / ip / udp /bootp / dhcp

            print ("[+] DHCP REquest with offeredip",offeredip)
            print ("[+] DHCP Server IP :",dhcpserverip)
            sendp(packet)

            print ("Operation complete...") 
