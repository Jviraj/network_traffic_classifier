from tkinter import *
import tkinter as tk
from tkinter import filedialog
from dataclasses import dataclass
from scapy.all import *
import csv
from collections import namedtuple
from ndpi import NDPI, NDPIFlow, ffi
# import argparse
import socket
import dpkt
# Dataset: https://www.unb.ca/cic/datasets/vpn.html


@dataclass
class pkt:
    src: int
    srcPort: int
    dst: int
    dstPort: int
    time: float
    size: int
    protocol: int


FLOW_KEY = "{} {}:{} <-> {}:{}"
FLOW_STR = "   {} {} [protocol:{}] [category:{}] [confidence:{}] [{} packets/{} bytes]"


PROTOCOL_UNKNWON = 0


class Flow(object):
    __slots__ = ("index",
                 "pkts",
                 "bytes",
                 "detected_protocol",
                 "ndpi_flow",
                 "src_port",
                 "dst_port",
                 "protocol")

    def __init__(self):
        self.pkts = 0
        self.detected_protocol = None
        self.bytes = 0
        self.ndpi_flow = None


ppacket = namedtuple('ParsedPacket', ['src_ip',
                                      'src_port',
                                      'dst_ip',
                                      'dst_port',
                                      'protocol',
                                      'ip_version',
                                      'ip_bytes'])


def inet_to_str(inet):
    """ get string representation of IP address """
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def parse_packet(pkt):
    """ parse packet and extract 5 tuple and IP bytes """
    try:
        l2 = dpkt.ethernet.Ethernet(pkt)
        if isinstance(l2.data, dpkt.ip.IP):
            ip_version = 4
        elif isinstance(l2.data, dpkt.ip6.IP6):
            ip_version = 6
        else:
            return
    except dpkt.dpkt.NeedData:
        return
    l3 = l2.data
    stop_decoding = False
    while not stop_decoding:
        if isinstance(l3.data, dpkt.tcp.TCP):
            l4 = l3.data
            proto = "TCP"
            stop_decoding = True
        elif isinstance(l3.data, dpkt.udp.UDP):
            l4 = l3.data
            proto = "UDP"
            stop_decoding = True
        elif isinstance(l3.data, dpkt.ip6.IP6):
            l3 = l3.data
        else:
            return

    return ppacket(src_ip=inet_to_str(l3.src), src_port=l4.sport,
                   dst_ip=inet_to_str(l3.dst), dst_port=l4.dport,
                   protocol=proto, ip_version=ip_version,
                   ip_bytes=bytes(l3))


def ppkt_to_flow_key(ppkt):
    """ create a consistent direction agnostic flow keyfrom a parsed packet """
    k = []
    if ppkt.src_ip < ppkt.dst_ip:
        # k = FLOW_KEY.format(ppkt.protocol, ppkt.src_ip, ppkt.src_port, ppkt.dst_ip, ppkt.dst_port)
        k.append(ppkt.protocol)
        k.append(ppkt.src_ip)
        k.append(ppkt.src_port)
        k.append(ppkt.dst_ip)
        k.append(ppkt.dst_port)
    else:
        if ppkt.src_ip == ppkt.dst_ip:
            if ppkt.src_port <= ppkt.dst_port:
                # k = FLOW_KEY.format(ppkt.protocol, ppkt.src_ip, ppkt.src_port, ppkt.dst_ip, ppkt.dst_port)
                k.append(ppkt.protocol)
                k.append(ppkt.src_ip)
                k.append(ppkt.src_port)
                k.append(ppkt.dst_ip)
                k.append(ppkt.dst_port)
            else:
                # k = FLOW_KEY.format(ppkt.protocol, ppkt.dst_ip, ppkt.dst_port, ppkt.src_ip, ppkt.src_port)
                k.append(ppkt.protocol)
                k.append(ppkt.dst_ip)
                k.append(ppkt.dst_port)
                k.append(ppkt.src_ip)
                k.append(ppkt.src_port)
        else:
            # k = FLOW_KEY.format(ppkt.protocol, ppkt.dst_ip, ppkt.dst_port, ppkt.src_ip, ppkt.src_port)
            k.append(ppkt.protocol)
            k.append(ppkt.dst_ip)
            k.append(ppkt.dst_port)
            k.append(ppkt.src_ip)
            k.append(ppkt.src_port)
    return k


class capture():
    def __init__(self):
        window = Tk()
        window.title('Network Classifier')
        # window.geometry("1000x500")
        self.screen_width = window.winfo_screenwidth()
        self.screen_height = window.winfo_screenheight()
        self.ratio = int(self.screen_width / 1920)
        self.ratio2 = self.screen_height/self.screen_width
        window.geometry(str(self.screen_width)+'x'+str(self.screen_height))
        window.config(background="White")
        self.label_network_classifier = Label(window,
                                              text="Network Classifier",
                                              width=100, height=4,
                                              fg="black", font=("bold", self.ratio*20))

        button_explore = Button(window,
                                text="Browse Files", font=("bold", self.ratio*20),
                                command=self.browseFiles)
        button_analyse = Button(window,
                                text="Analyse Capture", font=("bold", self.ratio*20),
                                command=lambda: self.Analyse(window))
        exit_button = Button(window,
                             text="Exit",
                             command=lambda: window.destroy(), font=("bold", self.ratio*20))

        self.label_network_classifier.place(
            x=int(self.screen_width/2), y=50, anchor="center")
        button_explore.place(x=int(self.screen_width/2) +
                             250*self.ratio, y=150/self.ratio2, anchor="center")
        button_analyse.place(x=int(self.screen_width/2) +
                             500*self.ratio, y=150/self.ratio2, anchor="center")
        exit_button.place(x=int(self.screen_width) - 300*self.ratio,
                          y=self.screen_height - 300*self.ratio*self.ratio2)

        window.mainloop()

    def browseFiles(self):
        self.filename = filedialog.askopenfilename(initialdir=".~/viraj/network_traffic_classifier",
                                                   title="Select a pcap file",
                                                   filetypes=(("pcap files", "*.pcap*"), ("allfiles", "*.*")))
        self.label_network_classifier.configure(
            text="File Opened:" + self.filename)
        print(self.filename)

    def Analyse(self, window):
        # def on_vertical_scroll(*args):
        #     self.mylist.yview(*args)

        # def on_horizontal_scroll(*args):
        #     self.mylist.xview(*args)

        pcap = []
        try:
            pcap.append(self.filename)
            frame = Frame(window, width=150, height=50)
            frame.place(x=self.screen_width/8, y=150 /
                        self.ratio2 - int(50*self.ratio2), anchor="nw", )

            # Create vertical scroll bar
            vertical_scrollbar = tk.Scrollbar(frame, orient="vertical")
            vertical_scrollbar.pack(side="right", fill="y")

            # Create horizontal scroll bar
            horizontal_scrollbar = tk.Scrollbar(frame, orient="horizontal")
            horizontal_scrollbar.pack(side="bottom", fill="x")

            self.mylist = Listbox(
                frame, yscrollcommand=vertical_scrollbar.set, xscrollcommand=horizontal_scrollbar.set, font=("bold", self.ratio*15), width=int(self.screen_width/25), height=int(50*self.ratio2))
            self.mylist.pack(fill="both", expand=True)

            vertical_scrollbar.config(command=self.mylist.yview)
            horizontal_scrollbar.config(command=self.mylist.xview)

            csvFile = 'output_app.csv'
            with open(csvFile, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Average size', 'Src Port',
                                'Dst Port', 'Protocol', 'Category'])
                for i in range(len(pcap)):
                    nDPI = NDPI()  # As simple as that. :)
                    flow_cache = {}  # We store the flows in a dictionary.
                    flow_count = 0  # Flow counter
                    keys = []
                    print("Using nDPI {}".format(nDPI.revision))

                    with open(pcap[i], 'rb') as pcap_file:
                        # We use dpkt pcap capture handler
                        capture = dpkt.pcap.Reader(pcap_file)
                        for time, packet in capture:
                            # Convert packet timestamp to milliseconds
                            time_ms = int(time * 1000)
                            ppkt = parse_packet(packet)
                            if ppkt is not None:  # If we succeed to parse the packet
                                key_1 = ppkt_to_flow_key(ppkt)
                                key = FLOW_KEY.format(
                                    key_1[0], key_1[1], key_1[2], key_1[3], key_1[4])
                                try:  # Try a Flow update
                                    flow = flow_cache[key]
                                    flow.detected_protocol = nDPI.process_packet(
                                        flow.ndpi_flow, ppkt.ip_bytes, time_ms, ffi.NULL)
                                    flow.pkts += 1
                                    flow.bytes += len(packet)
                                except KeyError:  # New Flow
                                    keys.append(key)
                                    flow = Flow()
                                    flow.index = flow_count
                                    flow_count += 1
                                    flow.ndpi_flow = NDPIFlow()  # We create an nDPIFlow object per Flow
                                    flow.detected_protocol = nDPI.process_packet(
                                        flow.ndpi_flow, ppkt.ip_bytes, time_ms, ffi.NULL)
                                    flow.pkts += 1
                                    flow.bytes += len(packet)
                                    flow.src_port = key_1[2]
                                    flow.dst_port = key_1[4]
                                    flow.protocol = key_1[0]
                                    flow_cache[key] = flow

                    print(" Label flows for: ", pcap[i])
                    unknown_flows = []
                    features = []
                    for key, flow in flow_cache.items():  # Iterate over all flows in flow cache
                        features = []
                        if flow.detected_protocol.app_protocol == PROTOCOL_UNKNWON:  # Didn't succeed to identigy it using DPI
                            # We try to guess it (port matching, LRU, etc.)
                            flow.detected_protocol = nDPI.giveup(
                                flow.ndpi_flow)
                        FLOW_EXPORT = FLOW_STR.format(flow.index,
                                                      key,
                                                      nDPI.protocol_name(
                                                          flow.detected_protocol),
                                                      nDPI.protocol_category_name(
                                                          flow.detected_protocol),
                                                      flow.ndpi_flow.confidence.name,
                                                      flow.pkts,
                                                      flow.bytes)
                        if flow.detected_protocol.app_protocol != PROTOCOL_UNKNWON:
                            # print(FLOW_EXPORT)  # We start by printing detected flows
                            features.append(int(flow.bytes/flow.pkts))
                            features.append(flow.src_port)
                            features.append(flow.dst_port)
                            if flow.protocol == "TCP":
                                features.append(1)
                            else:
                                features.append(0)
                            features.append(nDPI.protocol_category_name(
                                flow.detected_protocol))
                            writer.writerow(features)
                            self.mylist.insert(END, FLOW_EXPORT)
                            pass
                        else:
                            # Format it for later
                            features.append(int(flow.bytes/flow.pkts))
                            features.append(flow.src_port)
                            features.append(flow.dst_port)
                            if flow.protocol == "TCP":
                                features.append(1)
                            else:
                                features.append(0)
                            features.append("Unknown")
                            writer.writerow(features)
                            self.mylist.insert(END, FLOW_EXPORT)
                            pass
                            # unknown_flows.append(FLOW_EXPORT)
        except AttributeError:
            self.label_network_classifier.configure(
                text="Please select a pcap file!")
        pass

    # def startAnalyse(self):
    #     try:
    #         packets = rdpcap(self.filename)
    #         ipSrc = ipDst = Src = Dst = 0
    #         count = 0
    #         for packet in packets:
    #             size = len(packet)
    #             time = packet.time

    #             if IP in packet:
    #                 ipSrc = packet[IP].src
    #                 ipDst = packet[IP].dst
    #                 protocol = packet[IP].proto
    #             else:
    #                 continue
    #             if (TCP in packet) or (UDP in packet):
    #                 if TCP in packet:
    #                     Src = packet[TCP].sport
    #                     Dst = packet[TCP].dport
    #                 if UDP in packet:
    #                     Src = packet[UDP].sport
    #                     Dst = packet[UDP].dport
    #             else:
    #                 continue
    #             if TCP in packet:
    #                 print("TCP Size: {}, Protocol: {}, time: {}, Source: {}:{}, Destination: {}:{}, Seq: {}, Ack: {}".format(
    #                     size, protocol, time, ipSrc, Src, ipDst, Dst, packet.seq, packet.ack))
    #             else:
    #                 print("UDP Size: {}, Protocol: {}, time: {}, Source: {}:{}, Destination: {}:{}".format(
    #                     size, protocol, time, ipSrc, Src, ipDst, Dst))
    #             count = count + 1

    #         print(count)
    #     except AttributeError:
    #         self.label_network_classifier.configure(
    #             text="Please Select a file!")
    #     except FileNotFoundError:
    #         self.label_network_classifier.configure(text="File not found!")
    #     except:
    #         self.label_network_classifier.configure(
    #             text="Select only .pcap files!")


if __name__ == "__main__":
    pktcap = capture()
