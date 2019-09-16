import scapy.all as scapy


def scan(ip_adress):
    arp_request = scapy.ARP(pdst=ip_adress)                                                     
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    answered_list = []
    (answered_list, unanswered) = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    client_list =[]
    for element in answered_list:
        dictionary = {"IP": element[1].psrc, "MAC_address": element[1].hwsrc}
        client_list.append(dictionary)

    return client_list


def display(result):
    print("IP\t\t\t" + "MAC Address \n")
    print("------------------------------------------")
    for element in result:
        print(element["IP"] + "\t\t" + element["MAC_address"])




received_packet_info = scan("192.168.1.1/24")
display(received_packet_info)
