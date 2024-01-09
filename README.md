# SpaceDancers

For building topology
1. clean first: '''sudo mn -c'''
2. start ryu controller: '''ryu-manager timeoutAllocation.py'''
3. sudo python3 our_topology.py

If you want to replay network using the same hosts(same pcap file) run on mininet CLI:
4. h1 tcpreplay --intf1=h1-eth0 medium1
