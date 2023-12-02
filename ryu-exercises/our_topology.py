import subprocess
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI

class MyTopology(Topo):
    def build(self):
        # Add hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        # Add switch
        s1 = self.addSwitch('s1')

        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)

def start_mininet():
    topo = MyTopology()
    net = Mininet(topo)

    # Run Mininet with elevated privileges
    subprocess.call(["sudo", "mn"])

    net.start()
    
    # Run your Ryu controller here
    # For example:
    net.controller = net.addController(name='ryu', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Launch Ryu controller (replace 'your_controller.py' with your actual Ryu controller script)
    net.controller.cmd("ryu-manager ststRequest.py &")

    # Replay the pcap file into Mininet using tcpreplay
    subprocess.call(["sudo", "tcpreplay", "-i", "eth0", "univ1_pt1"])

    CLI(net)  # This drops you into a Mininet command prompt when the script is run

    net.stop()

if __name__ == '__main__':
    start_mininet()
