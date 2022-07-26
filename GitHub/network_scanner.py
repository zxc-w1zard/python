'''
from numpy import broadcast
import scapy.all as sc


def scan(ip):
    arp_request = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_request = broadcast/arp_request
    print(arp_broadcast_request.summary())


scan("93.181.250.6/24")


'''


import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]

    clients_list = []

    for i in answered_list:
        clients_dict = {"ip": i[1].psrc, "mac": i[1].hwsrc}
        clients_list.append(clients_dict)

    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")

    for i in results_list:
        print(i["ip"] + "\t\t" + i["mac"])


scan_result = scan("10.0.2.1/24")
print_result(scan_result)
