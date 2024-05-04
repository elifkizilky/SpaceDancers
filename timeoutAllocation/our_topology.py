import subprocess
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController
from scapy.all import *
import time
import threading
import requests

import constants

s1 =0
SWITCH_SIZE= constants.TABLE_SIZE #150 200 250 300

class MyTopology(Topo):
    
        
    def build(self):
        global s1
        # Add switch
        s1 = self.addSwitch('s1')

        #CREATING HOSTS AND ADDING LINKS
        for i in range(1, 3):
            name= 'h'+str(i)
            h= self.addHost(name)
            self.addLink(s1,h)

'''
#Creates hosts with certain address and macs
def create_hosts(topo):
    global s1
    hosts = {}
    macs= {}
    file_name= constants.FILE_NAME
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
'''

def set_flow_table_size(switch_name, flow_table_size):
    # Use ovs-vsctl command to set flow table size for the switch
    cmd = f"sudo ovs-vsctl -- --id=@ft create Flow_Table flow_limit={flow_table_size} overflow_policy=refuse -- set Bridge {switch_name} flow_tables=0=@ft"
    subprocess.call(cmd, shell=True)
 

#replay the same traffic on different hosts
def replay_traffic(host, pcap_file):
    print("STARTING TCP REPLAY FOR", pcap_file, " and ", host)
    cmd = 'sudo tcpreplay --intf1={} {}'.format(host.defaultIntf(), pcap_file)
    host.cmd(cmd)

def send_shutdown_signal():
    print("sending shutdown signal")
    requests.get('http://localhost:9999/shutdown')
    print("sent shutdown signal")

def start_mininet():
    
    topo = MyTopology()

    #hosts, macs = create_hosts(topo)

    controller = RemoteController('c0', ip='127.0.0.1', port=6633)
    net = Mininet(topo=topo, controller=controller)
    net.start()

    set_flow_table_size('s1', SWITCH_SIZE)
    print("STARTING SETTING IP ADDRESSES")
    #range 0 to 9 for univ2
    # 1 to 21 for univ1
    for i in range(1,21): # 1,3 for 2 pcap files
        hosts_and_pcaps=[]
        file_name= constants.FILE_NAME +str(i) #'univ1_pt'+str(i)
        print(file_name)
        #for 2 hosts: h1 and h2
        for i in range(1,3):
            name= 'h' + str(i)
            h= net.get(name)
            hosts_and_pcaps.append((h, file_name))
        
        print(hosts_and_pcaps)
        threads = []
        for (host, pcap) in hosts_and_pcaps:
            print("host", host, "pcap", pcap)
            thread = threading.Thread(target=replay_traffic, args=(host, pcap))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()
    send_shutdown_signal()
    CLI(net)
    net.stop()
    

if __name__ == '__main__':
    start_mininet()
    
