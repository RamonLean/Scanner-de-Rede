from scapy.all import ARP, Ether, srp
import argparse

parser = argparse.ArgumentParser(description = "Scanner de rede")

parser.add_argument("IP_Alvo", help="IP alvo (IP do roteador), exemplo :192.168.10.1/24")
argumentos = parser.parse_args()
target_ip = argumentos.IP_Alvo
# IP Address for the destination
# create ARP packet
arp = ARP(pdst=target_ip)
# create the Ether broadcast packet
# ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
# stack them
packet = ether/arp

result = srp(packet, timeout=3, verbose=0)[0]

# a list of clients, we will fill this in the upcoming loop
clientes = []

for sent, received in result:
    # for each response, append ip and mac address to `clients` list
    clientes.append({'ip': received.psrc, 'mac': received.hwsrc})

# print clients
print("Dispositivos na rede:")
print("IP" + " "*18+"MAC")
for cliente in clientes:
    print("{:16}    {}".format(cliente['ip'], cliente['mac']))
