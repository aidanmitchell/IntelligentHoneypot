#!/usr/local/bin/python2

import os #Needed for command line prompts
from scapy import all #Needed for scapy.all
from scapy.all import * #Needed for packet crafting

def packetcraft(): #defining packetcraft method

	while True: #Used to recraft packets when old ones are sent
	
	        os.system("iptables -A OUTPUT -p tcp -o eth0 --sport 1:65535 --tcp-flags RST RST -j DROP") #iptables rule to allow packets to be sent

	        def packet(pkt): #defining packet method

	            if pkt[TCP].flags == 2: #if the packet flags is equal to 2
	                if(str(pkt[TCP].dport)) == "22": #if the destination port is 22

	                        print('SYN packet detected port : ' + str(pkt[TCP].sport) + ' from IP Src : ' + pkt[IP].src) #Print out packet detected and the source of the packet 

	                        send(IP(dst=pkt[IP].src, src=pkt[IP].dst)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport,ack=pkt[TCP].seq + 1, flags='SA')) #send the new packet back which acknowledges the syn

	                elif(str(pkt[TCP].dport)) == "445": #if the destination port is 445

	                        print('SYN packet detected port : ' + str(pkt[TCP].sport) + ' from IP Src : ' + pkt[IP].src) #Print out packet detected and the source of the packet 


	                        send(IP(dst=pkt[IP].src, src=pkt[IP].dst)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport,ack=pkt[TCP].seq + 1, flags='SA')) #send the new packet back which acknowledges the syn


	        sniff(iface=conf.iface, prn=packet, filter="tcp[0xd]&18=2",count=100) #sniff the incoming packets on the main interface and call the packet method

	        os.system("iptables -D OUTPUT -p tcp -o eth0 --sport 1:65535 --tcp-flags RST RST -j DROP") #drop the iptables rule when the script has ran

def logports(): #defining the logports method

	os.system("tshark  \"tcp port 22\" or \"tcp port 445\" -i any -w honey.pcap -q & ") #log activity on ports 22 and 445 to honey.pcap file

def main(): #this main method runs first

	print("Intelligent Honeypot System") #print the title
        logports() #call the log ports method
	packetcraft() #call the packet crafting method

if __name__ == "__main__":
   try:
      main()
   except KeyboardInterrupt:
      print "Exiting as user request..."