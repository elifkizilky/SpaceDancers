import subprocess
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController
from scapy.all import *
import time
s1 =0
SWITCH_SIZE= 20
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
                hosts[src_ip] = src_host
                macs[src_host]= src_mac
                topo.addLink(s1,src_host)
    

            # Check if destination host exists, add if not
            if dst_ip not in hosts:
                dst_host = topo.addHost('h_' + dst_ip.replace('.', '_'))
                hosts[dst_ip] = dst_host
                macs[dst_host]= dst_mac
                topo.addLink(s1,dst_host)
     
    return hosts, macs
    
def set_flow_table_size(switch_name, flow_table_size):
    # Use ovs-vsctl command to set flow table size for the switch
    cmd = f"sudo ovs-vsctl -- --id=@ft create Flow_Table flow_limit={flow_table_size} overflow_policy=refuse -- set Bridge {switch_name} flow_tables=0=@ft"
    subprocess.call(cmd, shell=True) 

def start_mininet():
    
    topo = MyTopology()
    hosts, macs = create_hosts(topo, "univ1_pt1")

    controller = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo=topo, controller=controller)
    net.start()

    set_flow_table_size('s1', SWITCH_SIZE)
    for key, value in hosts.items():
        host= net.getNodeByName(value)
        host.setIP(key)
        host.setMAC(macs[value])
    time.sleep(5)
    # Replay the pcap file into Mininet using tcpreplay
    subprocess.call(["sudo", "tcpreplay", "-i","s1-eth1","--duration" ,"5","univ1_pt1"])
 
    CLI(net)  # This drops you into a Mininet command prompt when the script is run

    net.stop()

if __name__ == '__main__':
    start_mininet()
