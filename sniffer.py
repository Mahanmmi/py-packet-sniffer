import os

import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import AsyncSniffer, wrpcap
from scapy.plist import PacketList
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP


def print_sniffer(pkt: Ether):
    print(pkt.summary())


def sniff_routine() -> PacketList:
    sniffer = AsyncSniffer(prn=lambda x: x.summary(), filter='ip')

    while True:
        start = input("Type start to start capturing\n")
        if start == "start":
            print("Starting to capture...")
            break

    sniffer.start()

    while True:
        stop = input("To stop capturing type stop\n")
        if stop == "stop":
            break

    sniff_result = sniffer.stop()
    wrpcap("output/output.cap", sniff_result)
    return sniff_result


def analyzer(packet_list: PacketList):
    known_ports = pd.read_csv("service-names-port-numbers.csv")

    output = open('output/output.txt', 'w')
    output.write(str(packet_list) + "\n")
    output.write("\n----------------------------------------------------\n\n")

    src_count = dict()
    dst_count = dict()
    sport_count = dict()
    dport_count = dict()
    proto_count = dict()
    frag_count = 0
    min_size = packet_list[0][IP].len
    max_size = packet_list[0][IP].len
    total_size = 0

    for pkt in packet_list:
        src = pkt[IP].src
        if src in src_count:
            src_count[src] += 1
        else:
            src_count[src] = 1

        dst = pkt[IP].dst
        if dst in dst_count:
            dst_count[dst] += 1
        else:
            dst_count[dst] = 1

        protocol = pkt.sprintf("%IP.proto%")
        if protocol in proto_count:
            proto_count[protocol] += 1
        else:
            proto_count[protocol] = 1

        sport = pkt.sport
        sport_names = (known_ports.loc[
            (known_ports["Port Number"] == str(sport)) & (known_ports["Transport Protocol"] == protocol)])[
            "Service Name"].to_numpy()
        if len(sport_names) != 0 and sport_names[0] != "":
            sport = str(sport_names[0])
            sport += "(" + str(pkt.sport) + ")"
        if sport in sport_count:
            sport_count[sport] += 1
        else:
            sport_count[sport] = 1

        dport = pkt.dport
        dport_names = (known_ports.loc[
            (known_ports["Port Number"] == str(dport)) & (known_ports["Transport Protocol"] == protocol)])[
            "Service Name"].to_numpy()
        if len(dport_names) != 0 and dport_names[0] != "":
            dport = str(dport_names[0])
            dport += "(" + str(pkt.dport) + ")"
        if dport in dport_count:
            dport_count[dport] += 1
        else:
            dport_count[dport] = 1

        if "MF" in pkt[IP].flags or pkt[IP].frag != 0:
            frag_count += 1

        total_size += pkt[IP].len
        min_size = min(min_size, pkt[IP].len)
        max_size = max(max_size, pkt[IP].len)

    src_count = pd.DataFrame(sorted(src_count.items(), key=lambda item: item[1], reverse=True))
    src_count.columns = ["Sender(source) IP", "Datagram count"]
    src_count.loc[src_count["Datagram count"] >= 10].plot(kind="pie", y="Datagram count", startangle=90,
                                                          shadow=False,
                                                          labels=src_count["Sender(source) IP"], legend=False,
                                                          fontsize=6, title="Sender(source) IP")
    output.write(src_count.to_string() + "\n")
    output.write("\n----------------------------------------------------\n\n")

    dst_count = pd.DataFrame(sorted(dst_count.items(), key=lambda item: item[1], reverse=True))
    dst_count.columns = ["Receiver(destination) IP", "Datagram count"]
    dst_count.loc[dst_count["Datagram count"] >= 10].plot(kind="pie", y="Datagram count", startangle=90,
                                                          shadow=False,
                                                          labels=dst_count["Receiver(destination) IP"], legend=False,
                                                          fontsize=6, title="Receiver(destination) IP")
    output.write(dst_count.to_string() + "\n")
    output.write("\n----------------------------------------------------\n\n")

    sport_count = pd.DataFrame(sorted(sport_count.items(), key=lambda item: item[1], reverse=True))
    sport_count.columns = ["Sender(source) Port", "Datagram count"]
    sport_count.loc[sport_count["Datagram count"] >= 10].plot(kind="pie", y="Datagram count", startangle=90,
                                                              shadow=False,
                                                              labels=sport_count["Sender(source) Port"], legend=False,
                                                              fontsize=6, title="Sender(source) Port")
    output.write(sport_count.to_string() + "\n")
    output.write("\n----------------------------------------------------\n\n")

    dport_count = pd.DataFrame(sorted(dport_count.items(), key=lambda item: item[1], reverse=True))
    dport_count.columns = ["Receiver(destination) Port", "Datagram count"]
    dport_count.loc[dport_count["Datagram count"] >= 10].plot(kind="pie", y="Datagram count", startangle=90,
                                                              shadow=False,
                                                              labels=dport_count["Receiver(destination) Port"],
                                                              legend=False,
                                                              fontsize=6, title="Receiver(destination) Port")
    output.write(dport_count.to_string() + "\n")
    output.write("\n----------------------------------------------------\n\n")

    proto_count = pd.DataFrame(sorted(proto_count.items(), key=lambda item: item[1], reverse=True))
    proto_count.columns = ["Transport Layer Protocol", "Datagram count"]
    proto_count.plot(kind="pie", y="Datagram count", startangle=90,
                     shadow=False,
                     labels=proto_count["Transport Layer Protocol"],
                     legend=False,
                     fontsize=6, title="Transport Layer Protocol")
    output.write(proto_count.to_string() + "\n")
    output.write("\n----------------------------------------------------\n\n")

    output.write("Fragmented datagram count: " + str(frag_count) + "\n")
    output.write("\n----------------------------------------------------\n\n")

    average_size = total_size / len(packet_list)
    output.write("Smallest captured datagram size: " + str(min_size) + "\n")
    output.write("Largest captured datagram size: " + str(max_size) + "\n")
    output.write("Average captured datagram size: " + str(average_size) + "\n")
    output.write("\n----------------------------------------------------\n\n")

    output.close()
    plt.show()
    return None


def main():
    if not os.path.exists('output'):
        os.makedirs('output')
    sniff_result = sniff_routine()
    analyzer(sniff_result)
    print(sniff_result)


if __name__ == "__main__":
    main()
