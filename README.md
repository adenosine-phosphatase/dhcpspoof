# dhcpspoof
lightweight DHCP device impersonation client

In other words, dhcp client that will construct DHCP payload to mimic one of the predefined device profiles. 
In other words, you can select several types of devices you wish to mimic. 

The purpose of this DHCP manipulation is to trick device profilers into believeing your device is some other device (of your choice).

python scapydhcpclient.py [profile]
profile is one of the following:

"microsoft"
" Linux"
" CiscoAp" 
" HPLAsterJet"
" minimal"

"Minimal" sends minimum number of DHCP options in the packet (meant to be the stealthy one)
