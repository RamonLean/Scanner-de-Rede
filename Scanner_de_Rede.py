from scapy.all import ARP, Ether, srp
import argparse

parser = argparse.ArgumentParser(description = "Scanner de rede")

parser.add_argument("IP_Alvo", help="IP alvo (IP do roteador), exemplo :192.168.10.1/24")
argumentos = parser.parse_args()
target_ip = argumentos.IP_Alvo
# IP de destino
# Cra o pacote ARP
arp = ARP(pdst=target_ip)
# Cria o pacote Ether broadcast
# ff:ff:ff:ff:ff:ff Endereço MAC para broadcasting
ether = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ether/arp

result = srp(packet, timeout=3, verbose=0)[0]

#Uma lista de clientes encontrados na rede.
clientes = []

for sent, received in result:
    # Coloca Ip e endereço MAC na lista de clientes
    clientes.append({'ip': received.psrc, 'mac': received.hwsrc})

# Mostra na tela o resultado encontrado
print("Dispositivos na rede:")
print("IP" + " "*18+"MAC")
for cliente in clientes:
    print("{:16}    {}".format(cliente['ip'], cliente['mac']))
