# Adaptive Timeout Master for SDN

Software-Defined Networking (SDN) represents a transformative approach that decouples the data plane from the control plane in network architecture. Utilizing an Open- Flow controller, this framework populates the flow tables with necessary entries. Due to the imperative for rapid operation, flow tables possess a constrained capacity, necessitating the development of efficient management algorithms. In this research, there are two such approaches: proactive eviction and dynamic idle timeout allocation.
----------------------------------
## For building topology

1. clean first: '''sudo mn -c'''
2. start ryu controller: '''ryu-manager timeoutAllocation.py'''
3. sudo python3 our_topology.py

If you want to replay network using the same hosts(same pcap file) run on mininet CLI:
4. h1 tcpreplay --intf1=h1-eth0 medium1

### To retrieve univ2 trace
'''wget https://pages.cs.wisc.edu/~tbenson/IMC_DATA/univ2_trace.tgz'''

'''tar -xzf univ2_trace.tgz -C ./timeoutAllocation'''