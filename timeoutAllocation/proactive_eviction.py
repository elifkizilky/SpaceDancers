import heapq
from datetime import datetime
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ethernet, ether_types, packet
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from prettytable import PrettyTable

class ProactiveEvictionManager:
    def __init__(self, datapaths, totalNumFlows, table_size, flow_table, eviction_cache, eviction_data_table):
        self.datapaths = datapaths
        self.totalNumFlows = totalNumFlows
        self.table_size = table_size
        self.flow_table = flow_table
        self.eviction_cache = eviction_cache
        self.eviction_data_table = eviction_data_table

        #calculate heuristic
    def calculate_heuristic(self):
        temp_heap = []
        for key in self.eviction_data_table:
            if key in self.flow_table:
                packet_in = datetime.strptime(self.eviction_data_table[key]["packet_in_time"], "%Y-%m-%d %H:%M:%S")
                #last_hit = datetime.strptime(self.eviction_data_table[key]["last_hit_time"], "%Y-%m-%d %H:%M:%S")
                total_hits = 0
                if self.eviction_data_table[key].get("hit_count"):
                    total_hits = self.eviction_data_table[key]["hit_count"]
                current_time = datetime.now()
                #heuristic = ((last_hit - packet_in).total_seconds()/(current_time-packet_in).total_seconds())* total_hits
                self.eviction_data_table[key]["time passed now"] = (current_time-packet_in).total_seconds()
                heuristic = total_hits/( self.eviction_data_table[key]["time passed now"])
                
                #self.eviction_cache.setdefault(key, {})["heuristics"] = heuristic
                self.eviction_data_table[key]["heuristics"] = heuristic
                
                heapq.heappush(temp_heap, (heuristic, key))
        table = PrettyTable()
        table.field_names = ["Key", "heuristics"]
        
        self.eviction_cache = temp_heap

        for heuristic, key in self.eviction_cache:
            # Add each key and its corresponding heuristic to the table
            table.add_row([key, heuristic])

        #print('SELF EVICTION CACHE:\n' + table.get_string())
        #print("SELF EVICTION CACHE" , self.eviction_cache)

    def remove_flow(self, datapath, src, dst, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)

        mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            table_id=ofproto.OFPTT_ALL,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY
        )

        datapath.send_msg(mod)

    def proactive_eviction(self, table_occupancy):
        global totalNumFlows
        global table_size
        global table_occupancy

        #self.calculate_heuristic()
        high_threshold = 0.9
        low_threshold = 0.8

        
        if table_occupancy >= high_threshold:
            
            for dp in self.datapaths.values():
                self._request_stats(dp)
            
            
            # Wait specifically for the proactive eviction event
            self.proactive_eviction_event.wait()
            self.proactive_eviction_event.clear()
            # Continue with eviction if occupancy is still high
            
            if table_occupancy >= high_threshold:
                print("buraya girdi")
                temp_num_flows = totalNumFlows
                temp_occupancy = table_occupancy
                while temp_occupancy > low_threshold and self.eviction_cache:
                    # Pop the flow with the smallest heuristic value
                    _, key = heapq.heappop(self.eviction_cache)

                    # Extract src, dst, and in_port from key
                    src, dst, in_port = key.decode('utf-8').split('-')

                    # Evict flow from all datapaths
                    for datapath in self.datapaths.values():
                        self.remove_flow(datapath, src, dst, int(in_port))
                        temp_num_flows -= 1

                    # Update table occupancy
                    table_occupancy = totalNumFlows / table_size
                    temp_occupancy = temp_num_flows / table_size
                    print("CURRENT OCCUPANCY", table_occupancy)
                    print("TEMP OCCUPANCY", temp_occupancy)