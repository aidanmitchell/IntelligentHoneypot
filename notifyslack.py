from collections import Counter
import os
import slackweb
import socket

slack = slackweb.Slack(url="ENTER SLACK URL HERE")

def notification(count_ips):

	TopIP=[]
	NumberAttack=[]

	for ip, attacks in count_ips:

		TopIP.append(ip)
		NumberAttack.append(attacks)


	attachments = []

	if not TopIP:
		attachment = {"color": "#008000",
                              "title": "No IP's attacked today"}
	else:

	 	if len(TopIP) == 3:
			attachment = {"color": "#FF0000",
				      "title": "Top 3 Honeypot Attacker IP's:", 
				      "text" : "1." + str(TopIP[0]) + " - " + str(NumberAttack[0]) + " attacks" + "\n2." + str(TopIP[1]) + " - " + str(NumberAttack[1]) + " attacks" + "\n3." + str(TopIP[2]) + " - " + str(NumberAttack[2]) + " attacks"}
	
       		elif len(TopIP) == 2:
               		 attachment = {"color": "#FFA500",
                        	      "title": "Top 2 Honeypot Attacker IP's:",
                        	      "text" : "1." + str(TopIP[0]) + " - " + str(NumberAttack[0]) + " attacks" + "\n2." + str(TopIP[1]) + " - " + str(NumberAttack[1]) + " attacks"}

        	elif len(TopIP) == 1:
                	attachment = {"color": "#FFFF00",
                        	      "title": "Top Honeypot Attacker IP:",
				       "text" : "1." + str(TopIP[0]) + " - " + str(NumberAttack[0]) + " attacks"}
	
	attachments.append(attachment)
	slack.notify(attachments=attachments)


def getIPs():

	os.system("tshark -r .config/honey.pcap -T fields -e ip.src > .config/honey.txt") 
	localIP = socket.gethostbyname(socket.gethostname())

	ip_array=[]
	with open('.config/honey.txt') as ip_file:
	    for ip in ip_file:
		ip = ip.strip()
		if ip != str(localIP):
			ip_array.append(ip)
	
	count_ips=(Counter(ip_array).most_common())
	print count_ips
	return count_ips

def main():
	
	count_ips=getIPs()
	notification(count_ips)

if __name__ == "__main__":
   try:
      main()
   except KeyboardInterrupt:
      print "Exiting as user request..."