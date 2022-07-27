import argparse
import scapy.all as scapy

'''
from numpy import broadcast
import scapy.all as sc


def scan(ip):
    arp_request = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_request = broadcast/arp_request
    print(arp_broadcast_request.summary())


scan("")


'''

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


scan_result = scan("26.0.0.1/24")
print_result(scan_result)
'''


'''def scan(ip):
    arp_req_frame = scapy.ARP(pdst=ip)

    broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    answered_list = scapy.srp(
        broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]
    result = []
    for i in range(0, len(answered_list)):
        client_dict = {
            "ip": answered_list[i][1].psrc, "mac": answered_list[i][1].hwsrc}
        result.append(client_dict)

    return result
'''


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target',
                        help='Target IP Address/Adresses')
    options = parser.parse_args()

    # Check for errors i.e if the user does not specify the target IP Address
    # Quit the program if the argument is missing
    # While quitting also display an error message
    if not options.target:
        # Code to handle if interface is not specified
        parser.error(
            "[-] Please specify an IP Address or Addresses, use --help for more info.")
    return options


def scan(ip):
    arp_req_frame = scapy.ARP(pdst=ip)
    broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame
    answered_list = scapy.srp(
        broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]
    result = []
    for i in answered_list:
        client_dict = {"ip": i[1].psrc, "mac": i[1].hwsrc}
        result.append(client_dict)

    return result


def print_result(result_list):
    print("IP\t\t\tMAC Address\n----------------------------------")
    for client in result_list:
        print(client["IP"]+"\t\t"+client["mac"])


options = get_args()
scanned_output = scan(options.target)
print_result(scanned_output)
