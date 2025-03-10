from scapy.all import ARP, Ether, srp
import argparse

parser = argparse.ArgumentParser(description = "Network Scanner")
parser.add_argument("Target_IP", help="Example : sudo python3 network_scanner.py 192.168.10.1/24")
arguments = parser.parse_args()
target_ip = arguments.Target_IP
if not '/' in target_ip:
    print ("You need to use CIDR notation\nExample: sudo python3 network_Scanner.py 192.168.10.1/24 ")
    exit(1)
#ARP
arp = ARP(pdst=target_ip)
#Ether broadcast
#ff:ff:ff:ff:ff:ff MAC Address
ether = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ether/arp
try:
    result = srp(packet, timeout=3, verbose=0)[0]
except:
    print("You need to be root to run this scan. ")
    exit(1)

#List of clients founded in the network
clients = []

for sent, received in result:
    # Put the IP and the MAC addres in the clients list declare above.
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})

# Show the results on the screen.
print("Network devices:")
print("IP" + " "*18+"MAC")
for client in clients:
    print("{:16}    {}".format(client['ip'], client['mac']))