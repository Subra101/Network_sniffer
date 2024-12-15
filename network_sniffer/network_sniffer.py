import scapy.all as scapy
import pyshark
import sqlite3
import matplotlib.pyplot as plt
import seaborn as sns

class NetSniffer:
    def __init__(self, interface):
        self.interface = interface
        self.packets = []
        self.db = sqlite3.connect('netsniffer.db')
        self.cursor = self.db.cursor()
        self.cursor.execute("CREATE TABLE IF NOT EXISTS packets (src_ip TEXT, dst_ip TEXT, protocol TEXT, src_port INTEGER, dst_port INTEGER)")
        self.db.commit()

    def capture_packets(self, count=100):
        self.packets = scapy.sniff(iface=self.interface, count=count)

    def analyze_packets(self):
        for packet in self.packets:
            # Extract packet information using Scapy
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            protocol = packet.protocol

            # Analyze packet using PyShark
            pyshark_packet = pyshark.FileCapture(packet)
            packet_info = pyshark_packet[0]

            # Extract relevant information
            src_port = packet_info.transport_layer.srcport
            dst_port = packet_info.transport_layer.dstport

            # Store analysis results in the database
            self.cursor.execute("INSERT INTO packets (src_ip, dst_ip, protocol, src_port, dst_port) VALUES (?, ?, ?, ?, ?)",
                                (src_ip, dst_ip, protocol, src_port, dst_port))
            self.db.commit()

    def visualize_results(self):
        # Retrieve analysis results from the database
        self.cursor.execute("SELECT * FROM packets")
        results = self.cursor.fetchall()

        # Create a dictionary to store protocol usage
        protocol_usage = {}

        for result in results:
            protocol = result[2]
            if protocol in protocol_usage:
                protocol_usage[protocol] += 1
            else:
                protocol_usage[protocol] = 1

        # Create a bar chart using Matplotlib and Seaborn
        plt.figure(figsize=(10, 6))
        sns.barplot(x=list(protocol_usage.keys()), y=list(protocol_usage.values()))
        plt.xlabel('Protocol')
        plt.ylabel('Packet Count')
        plt.title('Protocol Usage')
        plt.show()

if __name__ == '__main__':
    interface = input("Enter the network interface (e.g., eth0, wlan0, etc.): ")
    netsniffer = NetSniffer(interface)
    netsniffer.capture_packets(count=100)
    netsniffer.analyze_packets()
    netsniffer.visualize_results()

    print("\n\n")
    print("\033[91mDeveloped by:\033[0m \033[94mHackerGPT\033[0m")
    print("\033[91mNetwork Hacker & Security Researcher\033[0m")
    print("\n\n")