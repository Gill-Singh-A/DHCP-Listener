# DHCP Listener
A Python Program that listens for DHCP Packets when a device connects to the same network on which our device is connected.

## Requirements
Language Used = Python3<br />
Modules/Packages used:
* os
* sys
* scapy
* datetime
* pickle
* optparse
* colorama
* time

## Inputs
* '-i', "--iface" : Interface on which sniffing has to be done
* '-v', "--verbose" : Display Useful Information related to the packets on the screen (True/False)(Default = True)
* '-w', "--write" : Dump the Packets to file
* '-r', "--read" : Read Packets from a dump file

## Output
It displays the MAC, Hostname and Vendor ID of the Device with the IP Address that the Device Requested depending upon the inputs provided by the user.