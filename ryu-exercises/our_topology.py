import subprocess
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController
from scapy.all import *
import time
s1 =0
SWITCH_SIZE= 750
class MyTopology(Topo):
    def build(self):
        global s1
        # Add switch
        s1 = self.addSwitch('s1')


def create_hosts(topo):
    global s1
    hosts = {}
    macs= {}
    file_name= "univ1_pt"
    hostID=1
    for i in range(1,2):
        print(hostID)
        pcap_file= file_name+str(i)
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
                    src_host = topo.addHost('h' + str(hostID))
                    #hosts[src_host]= src_ip
                    hosts[src_ip] = src_host
                    macs[src_host]= src_mac
                    topo.addLink(s1,src_host)
                    hostID += 1
                # Check if destination host exists, add if not
                if dst_ip not in hosts:
                    dst_host = topo.addHost('h' + str(hostID))
                    hosts[dst_ip] = dst_host
                    macs[dst_host]= dst_mac
                    topo.addLink(s1,dst_host)
                    hostID += 1
    print(hostID)
    return hosts, macs
    
def set_flow_table_size(switch_name, flow_table_size):
    # Use ovs-vsctl command to set flow table size for the switch
    cmd = f"sudo ovs-vsctl -- --id=@ft create Flow_Table flow_limit={flow_table_size} overflow_policy=refuse -- set Bridge {switch_name} flow_tables=0=@ft"
    subprocess.call(cmd, shell=True) 


def start_mininet():
    
    topo = MyTopology()

    hosts, macs = create_hosts(topo)

    controller = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo=topo, controller=controller)
    net.start()

    set_flow_table_size('s1', SWITCH_SIZE)
    print("STARTING SETTING IP ADDRESSES")
    for key, value in hosts.items():
        host= net.getNodeByName(value)
        host.setIP(key)
        host.setMAC(macs[value])
    
    h1= net.get('h1')
    print("STARTING TCP REPLAY")
    file_name= "univ1_pt"
    for i in range(1,2):
        pcap_file= file_name+str(i)
        print(pcap_file)
        output=h1.cmd('sudo tcpreplay --intf1=h1-eth0 {}'.format(pcap_file))
        print(output)
    CLI(net)
    net.stop()

if __name__ == '__main__':
    start_mininet()
