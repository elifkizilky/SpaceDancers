# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER #DEAD Dispatcher is added for monitoring
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import time
import hashlib
from datetime import datetime, timedelta
from prettytable import PrettyTable
import heapq
import psutil


#added for stats request
from ryu.lib import hub


#python related library for organizing data?
from operator import attrgetter
import threading

# Initialize a lock

data_table_lock = threading.Lock()
eviction_data_table_lock = threading.Lock()
eviction_cache_lock = threading.Lock()
totalNumFlows_lock = threading.Lock()
total_packet_in_lock = threading.Lock()
flow_table_lock = threading.Lock()
table_occupancy_lock = threading.Lock()

cookie=0
table_size=300  #just reading

totalNumFlows=  1 #table miss flow ---- more than one function writes --> mutex?
table_occupancy=1/table_size #only one function writes and others read so this is ok
rejected_flows = 0
total_packet_in_count = 0
overall_flow_number = 1
initial_lookup_count = 0  # Set this when you start monitoring
initial_matched_count = 0  # Set this when you start monitoring
lookup_count_diff=0

# PARAMETERS
tmax = 40
tmax_restore_value = tmax
minimum_tmax = 15


class SimpleMonitor13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def _proactive_eviction_loop(self):
        global table_occupancy
        while True:
            table_occupancy = totalNumFlows/table_size
            self.proactive_eviction()
            time.sleep(2)  # Run proactive eviction every 2 seconds
            
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        
        # Initialize the accumulators and count for averaging
        self.table_occupancy_total = 0
        self.cpu_usage_total = 0
        self.memory_usage_total = 0
        self.average_accumulation_count = 0
        
        self.first_packet_in_time = None
        self.last_flow_removed_time = None
        self.first_packet_received = False
        
        self.data_table = {}  # Dictionary to hold flow attributes
        self.eviction_cache = {} # dictionary to hold flows that will be evicted (key,heut)
        self.eviction_data_table = {}
        self.mac_to_port = {}
        self.datapaths = {}
        self.start_time = datetime.now()
        self.monitor_thread = hub.spawn(self._monitor)
        self.average_calculation_thread = hub.spawn(self._calculate_averages)
        self.flow_table = set()
        self.proactive_eviction_event = threading.Event()
        self.proactive_eviction_thread = threading.Thread(target=self._proactive_eviction_loop)
        self.proactive_eviction_thread.daemon = True
        self.proactive_eviction_thread.start()

    
    

        
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
        
        '''
        table = PrettyTable()
        table.field_names = ["Key", "heuristics"]
        
        self.eviction_cache = temp_heap

        for heuristic, key in self.eviction_cache:
            # Add each key and its corresponding heuristic to the table
            table.add_row([key, heuristic])

        #print('SELF EVICTION CACHE:\n' + table.get_string())
        #print("SELF EVICTION CACHE" , self.eviction_cache)
        '''
     
   
    def set_idle_timeout(self, key):
        global table_occupancy
        global totalNumFlows
        global table_size
        global tmax
        global tmax_restore_value
        global minimum_tmax
        t_init = 1  # Initial value for idle time
        idle_timeout = t_init
        table_occupancy=totalNumFlows/table_size #FRACTION POINT FIX
        coef95 = 0.9
        b_value = 1
        #print("TABLE OCCUPANCY IS %f" % (table_occupancy))
       
        # only last_packet_in field exist on the self.data_table, flow is newly come
        if key in self.data_table and len(self.data_table[key]) == 1 and 'last_packet_in' in self.data_table[key]:
            idle_timeout = t_init  # Initialize idle time
            #print("1. print %s" % (key), idle_timeout)
            npacketIn = 1
        else:
            npacketIn = self.data_table.get(key).get('packet_count', 1)
            #npacketIn += 1
            #print("N_PACKET_IN FOR THE FLOW %s IS %d" % (key, npacketIn))   
            if table_occupancy <=  0.60:
                idle_timeout = min(t_init * 2 ** npacketIn, tmax)
                tmax = tmax_restore_value #restore the tmax if occupancy is low
                #print("2. print key: %s nacketIn: %d t_init: %d idle_timeout: " % (key, npacketIn, t_init), idle_timeout)
            elif table_occupancy <= 0.95: #there is a mistake in here
                tmax = max(tmax * coef95 - b_value, minimum_tmax)
                date_format="%Y-%m-%d %H:%M:%S"
                tpacketInStr = self.data_table.get(key).get('last_packet_in', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                tlastRemovedStr = self.data_table.get(key).get('last_removed', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                tlastDuration = self.data_table.get(key).get('last_duration', (datetime.strptime(tpacketInStr,date_format) - datetime.strptime(tlastRemovedStr,date_format)).total_seconds())
    
                if tpacketInStr and tlastRemovedStr:
                    
                    tpacketIn=datetime.strptime(tpacketInStr,date_format)
                    tlastRemoved=datetime.strptime(tlastRemovedStr,date_format)
                    if (tpacketIn - tlastRemoved).total_seconds() <= tlastDuration:
                       
                        idle_timeout = int(min(tlastDuration + (tpacketIn - tlastRemoved).total_seconds(), tmax))
                        #print("3.deki değiştirmeden önceki timeout" ,idle_timeout)
                        #print("çıkarmadan 2.si", (tpacketIn - tlastRemoved).total_seconds())
                        if idle_timeout <  1:
                            idle_timeout = 1
                        #print("3. print %s t_last_duration: %d tpacketIn: %s tlastRemoved: %s idle timeout: " % (key, tlastDuration, tpacketIn ,tlastRemoved), idle_timeout)
                    else:
                        if int(tlastDuration) > 0: 
                            idle_timeout = int(tlastDuration)
                            #print("4. print %s t_lastduration: %d" % (key, tlastDuration), idle_timeout)
                        else:
                            idle_timeout = 1
                            #print("5. print %s" % (key), idle_timeout)
                        
            
            elif table_occupancy > 0.95:
                idle_timeout = 1
                #print("6. print %s" % (key), idle_timeout)
            
       
       
        return idle_timeout
        


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
                
    def generate_key(self, eth_src, eth_dst, in_port):
        # Concatenate eth_src, eth_dst, and in_port values
        combined_values = f"{eth_src}-{eth_dst}-{in_port}".encode('utf-8')

        # Generate a hash value
        #cookie = hashlib.sha256(combined_values).hexdigest()
        #cookie_int = int(cookie, 16)

        #print("COOKIE ", cookie_int)
        #print("COOKIE ", combined_values)
        return combined_values

    # This function checks and removes entries from the data table
    def check_and_delete_entries(self):
        current_time = datetime.now()
        elapsed_time = (current_time - self.start_time).total_seconds()
        #print("ELAPSED TIME %f" % (elapsed_time))
        entries_to_delete = []
        DeleteThreshold = 90  # Define your DeleteThreshold constant here

        for key, attributes in self.data_table.items():
            last_removed_str = attributes.get('last_removed')
            if last_removed_str:
                #last_removed_dt = datetime.strptime(last_removed_str, "%Y-%m-%d %H:%M:%S")

                last_duration = attributes.get('last_duration', 0)
                # Creating a timedelta object representing a duration of 90 seconds
                #delete_threshold = timedelta(seconds=DeleteThreshold)

                if last_duration + DeleteThreshold < elapsed_time:
                    entries_to_delete.append(key)

        # Remove entries that meet the deletion condition
        for key in entries_to_delete:
            print("%s DELETED FROM DATA TABLE" % (key))
            del self.data_table[key]
     
     
    def _calculate_averages(self):
        temp_last_removed = None
        while True:
            # Check if the first packet has been received and last flow removed
            if self.first_packet_received and self.last_flow_removed_time:
               
                total_time_passed = (self.last_flow_removed_time - self.first_packet_in_time).total_seconds()
                if total_time_passed > 0:
                    # Calculate averages
                    avg_table_occupancy = self.table_occupancy_total / total_time_passed
                    avg_cpu_usage = self.cpu_usage_total / total_time_passed
                    avg_memory_usage = self.memory_usage_total / total_time_passed

                    # Print average values
                    print("##############################--------------##############################")
                    print(f"Average Table Occupancy over {total_time_passed}: {avg_table_occupancy}")
                    print(f"Average CPU Usage over {total_time_passed}: {avg_cpu_usage}%")
                    print(f"Average Memory Usage over {total_time_passed}: {avg_memory_usage}%")
                    print("##############################--------------##############################")
            
            if temp_last_removed != self.last_flow_removed_time:
                # Continue accumulating values every second
                self.table_occupancy_total += totalNumFlows / table_size
                self.cpu_usage_total += psutil.cpu_percent(interval=None)/100
                self.memory_usage_total += psutil.virtual_memory().percent/100
                temp_last_removed = self.last_flow_removed_time

            
            hub.sleep(1) 

    #send stats request every 10s
    def _monitor(self):
        global rejected_flows
        global table_occupancy
        global total_packet_in_count
        global totalNumFlows
        global table_size
        global overall_flow_number
        global lookup_count_diff
        
        average_interval = 15
        
        while True:
            datapaths_snapshot = list(self.datapaths.values())
            for dp in datapaths_snapshot:
                #self._request_stats(dp)
               
                #self.remove_flow(dp, 2)
                self.send_table_stats_request(dp)
                #self.check_and_delete_entries() #sonra aç
                #print("Data table: ", self.display_data_table())
                #self.display_data_table()
                #self.calculate_heuristic()
                #print("DATA TABLE FOR PROACTIVE", self.display_eviction_data_table())
                print("##############################--------------##############################")
                print("REJECTED FLOWS", rejected_flows)
                #print("FLOW TABLE", self.flow_table)
                print("TOTAL PACKET COUNT", total_packet_in_count)
                print("TOTAL HIT COUNT", lookup_count_diff-total_packet_in_count - rejected_flows)
                if lookup_count_diff != 0:
                    miss_rate = (total_packet_in_count + rejected_flows) / lookup_count_diff
                    print("MISS RATE:", miss_rate)
                else:
                    print("MISS RATE: Division by zero avoided. Lookup count difference is zero.")
                print("OVERALL FLOW NUMBER", overall_flow_number)
                table_occupancy = totalNumFlows/table_size
                print("TABLE OCCUPANCY", table_occupancy)
                print("TOTAL NUM FLOWS", totalNumFlows)
                #print("FLOW TABLE", self.flow_table)
                
                cpu_usage = psutil.cpu_percent(interval=1)
                memory_usage = psutil.virtual_memory().percent
                print(f"CPU Usage: {cpu_usage}%, Memory Usage: {memory_usage}%")
                print("##############################--------------##############################")
            hub.sleep(5)

    def display_data_table(self):
        table = PrettyTable()
        table.field_names = ["Key", "Packet Count", "Last Packet In", "Last Removed", "Last Duration", "Idle timeout"]

        for key, attributes in self.data_table.items():
            table.add_row([key, attributes.get("packet_count"), attributes.get("last_packet_in"), attributes.get("last_removed"), attributes.get("last_duration"), attributes.get("idle_timeout")])

        print('Data Table:\n' + table.get_string())
        
        
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)


    def display_eviction_data_table(self):
        table = PrettyTable()
        table.field_names = ["Key", "Idle Timeout", "Packet In Time", "Total number of hits", "Heuristics", "Time Passed Until Now"]

        for key, attributes in self.eviction_data_table.items():
            table.add_row([key, attributes.get("idle_timeout"), attributes.get("packet_in_time"), attributes.get("hit_count"), attributes.get("heuristics"), attributes.get("time passed now")])

        print('Eviction Data Table:\n' + table.get_string())
    


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.send_flow_stats_request(datapath)
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_miss_entry_flow(datapath, 0, match, actions)

    def add_miss_entry_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        flags = ofproto.OFPFF_SEND_FLOW_REM
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=0, hard_timeout=0, priority=priority, match=match,
                                    instructions=inst, flags= flags)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=0, hard_timeout=0, match=match, instructions=inst, flags= flags)
        datapath.send_msg(mod)
        
        
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        global cookie
        global totalNumFlows
        global total_packet_in_count
        global table_occupancy
        global overall_flow_number
        
          
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid= datapath.id
        src = match["eth_src"]
        dst = match["eth_dst"]
        in_port = match["in_port"]
        key = self.generate_key(src, dst,in_port )
            
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions)]
        flags = ofproto.OFPFF_SEND_FLOW_REM
            
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            
        if key in self.flow_table:
            if key in self.data_table:
                allocatedTimeout = self.data_table[key].get("idle_timeout", 0)
            else:
                allocatedTimeout = self.set_idle_timeout(key)
             
        else:
            # Update only the last_packet_in attribute, preserving other attributes
            existing_flow_attributes = self.data_table.get(key, {})
            
            # take the first packet-in as start
            if not self.first_packet_received:
                self.first_packet_in_time = datetime.now()
                self.first_packet_received = True
            
            existing_flow_attributes['last_packet_in'] = current_time
            self.data_table[key] = existing_flow_attributes
                
            allocatedTimeout = self.set_idle_timeout(key)
            with totalNumFlows_lock:
                totalNumFlows += 1 #increase the number of flows since I'm adding to flow table
                overall_flow_number += 1
            #print("arttırdım", totalNumFlows)
            table_occupancy=totalNumFlows/table_size
            #print(f"totalNumFLows before adding to flow table {totalNumFlows} with {key}")
            
            with flow_table_lock:
                self.flow_table.add(key)
                
            if key in self.eviction_data_table:
                with eviction_data_table_lock: 
                    self.eviction_data_table[key]["packet_in_time"] = current_time
                    self.eviction_data_table[key]["hit_count"] = 0
            else:
                with eviction_data_table_lock:
                    self.eviction_data_table.setdefault(key, {})["packet_in_time"] = current_time
                    self.eviction_data_table[key]["hit_count"] = 0
                    
            if key in self.data_table:
                packet_count = self.data_table.get(key).get("packet_count", 0)
                packet_count += 1
                with data_table_lock:
                    self.data_table[key]["packet_count"] = packet_count
                    
                    
            else:
                with data_table_lock:
                    self.data_table[key] = {"packet_count" : 1}
            
            
        #print("ALLOCATED TIMEOUT FOR THE FLOW %s IS %d" % (key, allocatedTimeout))
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=allocatedTimeout, hard_timeout=0, priority=priority, match=match,
                                    instructions=inst, flags= flags)
                
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=allocatedTimeout, hard_timeout=0, match=match, instructions=inst, flags= flags)
            
            
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        if key in self.data_table:
            with data_table_lock:
                self.data_table[key]["idle_timeout"] = allocatedTimeout
            #print("arttırıldı", key)
            #self.eviction_data_table[key]["packet_count"] = packet_count
        else:
            with data_table_lock:
                self.data_table[key] = {"idle_timeout": allocatedTimeout}  # Initialize packet_count as 1 for the new key
            
        

        #last_hit_time field update regardless of being in flow table
        if key not in self.eviction_data_table:
            # If the key doesn't exist, set the value for the key using setdefault
            with eviction_data_table_lock:
                self.eviction_data_table.setdefault(key, {})["idle_timeout"] = allocatedTimeout
                
            #self.eviction_data_table[key]["last_hit_time"] = current_time 
        else:
            # If the key exists, update the value
            with eviction_data_table_lock:
                self.eviction_data_table[key]["idle_timeout"] = allocatedTimeout
            #self.eviction_data_table[key]["last_hit_time"] = current_time 
           
        with total_packet_in_lock:
            total_packet_in_count += 1
        datapath.send_msg(mod)
            
 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        global rejected_flows
        
        
       
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        key = self.generate_key(src, dst, in_port)
      

       
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        
        
            
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                #if there is space in table_size, add flow
                if totalNumFlows < table_size:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                   
                elif key not in self.flow_table: #check this condition??
                    rejected_flows += 1
                return
            else:
                if totalNumFlows < table_size:
                    self.add_flow(datapath, 1, match, actions)
                elif key not in self.flow_table:
                    rejected_flows += 1

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
     
        
      
            
    #to delete flow rule
  
  
    def send_flow_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0 #not applying any filtering based on the cookie value
        match = ofp_parser.OFPMatch(in_port=1)
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                             ofp.OFPTT_ALL,
                                             ofp.OFPP_ANY, ofp.OFPG_ANY,
                                             cookie, cookie_mask,
                                             match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
         
        flows = []
        table = PrettyTable()
        table.field_names = ["Table ID", "Duration (Sec)", "Priority", "Idle Timeout", "Hard Timeout", "Cookie", "Packet Count", "Byte Count", "Match", "Instructions"]
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                         'duration_sec=%d duration_nsec=%d '
                         'priority=%d '
                         'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                         'cookie=%d packet_count=%d byte_count=%d '
                         'match=%s instructions=%s' %
                         (stat.table_id,
                          stat.duration_sec, stat.duration_nsec,
                          stat.priority,
                          stat.idle_timeout, stat.hard_timeout, stat.flags,
                          stat.cookie, stat.packet_count, stat.byte_count,
                          stat.match, stat.instructions))
            table.add_row([stat.table_id,
                       f"{stat.duration_sec} s",
                       stat.priority,
                       stat.idle_timeout,
                       stat.hard_timeout,
                       stat.cookie,
                       stat.packet_count,
                       stat.byte_count,
                       stat.match,
                       stat.instructions])
            
            #print(type(stat.match))
            if 'in_port' in stat.match and 'eth_src' in stat.match and 'eth_dst' in stat.match:
                in_port = stat.match['in_port']
                eth_src = stat.match['eth_src']
                eth_dst = stat.match['eth_dst']
                #print(in_port)
                key = self.generate_key(eth_src,eth_dst,in_port)
                if key in self.flow_table:
                    if key in self.eviction_data_table:
                        with eviction_data_table_lock:
                            self.eviction_data_table[key]["hit_count"] = stat.packet_count
                    else:
                        with eviction_data_table_lock:
                            self.eviction_data_table.setdefault(key, {})["hit_count"] = stat.packet_count
                #print(eth_src)
                #print(eth_dst)
            
            #self.logger.info('FlowStats:\n' + table.get_string())
        #print('FlowStats:\n' + table.get_string())
        self.calculate_heuristic()
        #print("DATA TABLE FOR PROACTIVE", self.display_eviction_data_table())
        # Signal that stats reply has been handled, specifically for proactive eviction
        self.proactive_eviction_event.set()
                

        
            
        #self.logger.debug('FlowStats: %s', flows)
        #print('FlowStats: %s' % flows)
        
        
        
    
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        global totalNumFlows
       
        self.last_flow_removed_time = datetime.now()
            
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'
            '''
        print(msg.cookie, msg.priority, reason, msg.table_id,
            msg.duration_sec, msg.duration_nsec,
            msg.idle_timeout, msg.hard_timeout,
            msg.packet_count, msg.byte_count, msg.match)
            '''
        self.logger.debug('OFPFlowRemoved received: '
                        'cookie=%d priority=%d reason=%s table_id=%d '
                        'duration_sec=%d duration_nsec=%d '
                        'idle_timeout=%d hard_timeout=%d '
                        'packet_count=%d byte_count=%d match.fields=%s',
                        msg.cookie, msg.priority, reason, msg.table_id,
                        msg.duration_sec, msg.duration_nsec,
                        msg.idle_timeout, msg.hard_timeout,
                        msg.packet_count, msg.byte_count, msg.match)
        
        dst = msg.match["eth_dst"]
        src = msg.match["eth_src"]
        in_port = msg.match["in_port"]
        key = self.generate_key(src,dst,in_port)
        # Get the existing flow attributes
        existing_flow_attributes = self.data_table.get(key, {})

        # Get the current time in a suitable format
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        # Assuming 'last_packet_in' and 'last_removed' are strings representing timestamps
        last_packet_in_str = existing_flow_attributes['last_packet_in']

        # Convert strings to datetime objects
        last_packet_in_dt = datetime.strptime(last_packet_in_str, "%Y-%m-%d %H:%M:%S")
        last_removed_dt = datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")

        # Calculate the duration
        duration = last_removed_dt - last_packet_in_dt

        # Update only the last_removed attribute, preserving other attributes
        existing_flow_attributes['last_removed'] = current_time
        existing_flow_attributes['last_duration'] = duration.total_seconds()
        

        # Update the flow table with the modified flow attributes
        with data_table_lock:
            self.data_table[key] = existing_flow_attributes
        #self.eviction_data_table[key]["hit_count"] = 0 #update the hit count to 0 when flow is removed.
        
        if key in self.flow_table: 
            with totalNumFlows_lock:
                totalNumFlows -= 1
                #print("azalttım", totalNumFlows)
                with flow_table_lock:
                    self.flow_table.discard(key)
        
        #delete the key from the eviction data table
        if key in self.eviction_data_table:
            with eviction_data_table_lock:
                del self.eviction_data_table[key]
        
        if key in self.eviction_cache:
            with eviction_data_table_lock:
                del self.eviction_cache[key]
        
        #print("AZALTTIM")



    def send_table_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPTableStatsRequest(datapath, 0)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
    def table_stats_reply_handler(self, ev):
        global initial_lookup_count
        global initial_matched_count
        global lookup_count_diff
        tables = []
        for stat in ev.msg.body:
            tables.append('table_id=%d active_count=%d lookup_count=%d '
                        ' matched_count=%d' %
                        (stat.table_id, stat.active_count,
                        stat.lookup_count, stat.matched_count))
            if stat.table_id==0:
                '''
                if initial_lookup_count == 0 and initial_matched_count == 0:
                    initial_lookup_count = stat.lookup_count
                    initial_matched_count = stat.matched_count
                '''
                print('TableStats: %s', stat)
                # Calculate the difference from the initial counts
                lookup_count_diff = stat.lookup_count
                matched_count_diff = stat.matched_count
                print(f'Lookup Count: {lookup_count_diff}, Matched Count: {matched_count_diff}')

                
                #print("flow table ratio: %s" % (stat.active_count/table_size*100))
                #table_occupancy = (stat.active_count/table_size*100)
        
        self.logger.debug('TableStats: %s', tables)
        
        
    def remove_flow(self, datapath, src, dst, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)

        # Create a flow mod message to delete the flow
        mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            table_id=ofproto.OFPTT_ALL,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY
        )

        datapath.send_msg(mod)
               
            
    def proactive_eviction(self):
        global totalNumFlows
        global table_size
        global table_occupancy

        #self.calculate_heuristic()
        high_threshold = 0.85
        low_threshold = 0.50

        
        if table_occupancy >= high_threshold:
            
            for dp in self.datapaths.values():
                self._request_stats(dp)
            
            
            # Wait specifically for the proactive eviction event
            self.proactive_eviction_event.wait()
            self.proactive_eviction_event.clear()
            # Continue with eviction if occupancy is still high
            
            if table_occupancy >= high_threshold:
                print("####### STARTING PROACTIVE EVICTION #######")
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
                    with table_occupancy_lock:
                        table_occupancy = totalNumFlows / table_size
                    temp_occupancy = temp_num_flows / table_size
                    print("CURRENT OCCUPANCY", table_occupancy)
                    print("TEMP OCCUPANCY", temp_occupancy)

