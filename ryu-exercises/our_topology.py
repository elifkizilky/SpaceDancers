import subprocess
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController
from scapy.all import *
s1 =0
class MyTopology(Topo):
    def build(self):
        global s1
        # Add hosts
        #h1 = self.addHost('h1')
        #h2 = self.addHost('h2')
        #h3 = self.addHost('h3')

        # Add switch
        s1 = self.addSwitch('s1')

        # Add links
        #self.addLink(h1, s1)
        #self.addLink(h2, s1)
        #self.addLink(h3, s1)
def create_hosts(topo, pcap_file):
    global s1
    hosts = {}
    macs= {}
    print("before rdpcap")
    pkts = rdpcap(pcap_file)
    print("after rdpcap")

    
    for pkt in pkts:
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src
                dst_mac = pkt[Ether].dst
            # Check if source host exists, add if not
            if src_ip not in hosts:
                src_host = topo.addHost('h_' + src_ip.replace('.', '_'))
                #src_host.setIP(src_ip)
                print(src_host)
                hosts[src_ip] = src_host
                macs[src_host]= src_mac
                topo.addLink(s1,src_host)
                print("added: ", src_ip)

            # Check if destination host exists, add if not
            if dst_ip not in hosts:
                dst_host = topo.addHost('h_' + dst_ip.replace('.', '_'))
                hosts[dst_ip] = dst_host
                macs[dst_host]= dst_mac
                topo.addLink(s1,dst_host)
                print("added dest: " , dst_ip)
            print(topo.nodes())
    print("hosts",topo.hosts())
       
    print("nodes",topo.nodes())
     
    return hosts, macs
    
  

def start_mininet():
    topo = MyTopology()
    hosts, macs = create_hosts(topo, "my.pcap")
    print("hosts inside start-mininet",hosts)

    for key, value in hosts.items():
        print(f"{key}: {value}")
    controller = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo=topo, controller=controller)

    net.start()
    for key, value in hosts.items():
        host= net.getNodeByName(value)
        print(host)
        host.setIP(key)
        host.setMAC(macs[value])
    
    # Replay the pcap file into Mininet using tcpreplay
    subprocess.call(["sudo", "tcpreplay", "-i","s1-eth1","--duration" ,"5","my.pcap"])
    #subprocess.call(["sudo", "tcpreplay", "-i","s1-eth2","--duration" ,"5","my.pcap"])
    #subprocess.call(["sudo", "tcpreplay", "-i","s1-eth3","--duration" ,"5","my.pcap"])
    #subprocess.call(["sudo", "tcpreplay", "-i","s1-eth4","--duration" ,"5","my.pcap"])
    CLI(net)  # This drops you into a Mininet command prompt when the script is run

    net.stop()

if __name__ == '__main__':
    start_mininet()
