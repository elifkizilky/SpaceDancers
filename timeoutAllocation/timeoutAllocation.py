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


#added for stats request
from ryu.lib import hub


#python related library for organizing data?
from operator import attrgetter
import threading

# Initialize a lock
totalNumFlows_lock = threading.Lock()

cookie=0
table_size=100  #just reading
#npacketIn=0
totalNUmFLows=  1 #table miss flow ---- more than one function writes --> mutex?
table_occupancy=1/table_size #only one function writes and others read so this is ok
rejected_flows = 0
total_packet_in_count = 0
class SimpleMonitor13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.data_table = {}  # Dictionary to hold flow attributes
        self.eviction_cache = {} # dictionary to hold flows that will be evicted (key,heut)
        self.eviction_data_table = {}
        self.mac_to_port = {}
        self.datapaths = {}
        self.start_time = datetime.now()
        self.monitor_thread = hub.spawn(self._monitor)
        self.flow_table = set()
       
        
    #calculate heuristic
    def calculate_heuristic(self):
        
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
                
                self.eviction_cache.setdefault(key, {})["heuristics"] = heuristic
                self.eviction_data_table[key]["heuristics"] = heuristic
        table = PrettyTable()
        table.field_names = ["Key", "heuristics"]

        for key, attributes in self.eviction_cache.items():
            table.add_row([key, attributes.get("heuristics")])

        #print('SELF EVICTION CACHE:\n' + table.get_string())
        #print("SELF EVICTION CACHE" , self.eviction_cache)
    
     
    #get the table_occupancy globally
    def set_idle_timeout(self, key):
        global table_occupancy
        global totalNUmFLows
        global table_size
        t_init = 1  # Initial value for idle time
        idle_timeout = t_init
        tmax = 32  # Maximum idle time
        
        table_occupancy=totalNUmFLows/table_size #FRACTION POINT FIX
        print("TABLE OCCUPANCY IS %f" % (table_occupancy))
       
        
        DeleteThreshold = 90 #for deleting flows from data table
        coef95 = 0.9
        b_value = 1
        
        # only last_packet_in field exist on the self.data_table, flow is newly come
        if key in self.data_table and len(self.data_table[key]) == 1 and 'last_packet_in' in self.data_table[key]:
            idle_timeout = t_init  # Initialize idle time
            print("1. print %s" % (key), idle_timeout)
            npacketIn = 1
        else:
            npacketIn = self.data_table.get(key).get('packet_count', 1)
            #npacketIn += 1
            #print("N_PACKET_IN FOR THE FLOW %s IS %d" % (key, npacketIn))   
            if table_occupancy <=  0.75:
                idle_timeout = min(t_init * 2 ** npacketIn, tmax)
                print("2. print key: %s nacketIn: %d t_init: %d idle_timeout: " % (key, npacketIn, t_init), idle_timeout)
            elif table_occupancy <= 0.95: #there is a mistake in here
                tmax = tmax * coef95 - b_value
                date_format="%Y-%m-%d %H:%M:%S"
                tpacketInStr = self.data_table.get(key).get('last_packet_in', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                tlastRemovedStr = self.data_table.get(key).get('last_removed', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                tlastDuration = self.data_table.get(key).get('last_duration', (datetime.strptime(tpacketInStr,date_format) - datetime.strptime(tlastRemovedStr,date_format)).total_seconds())
    
                if tpacketInStr and tlastRemovedStr:
                    
                    tpacketIn=datetime.strptime(tpacketInStr,date_format)
                    tlastRemoved=datetime.strptime(tlastRemovedStr,date_format)
                    if (tpacketIn - tlastRemoved).total_seconds() <= tlastDuration:
                       
                        idle_timeout = int(min(tlastDuration + (tpacketIn - tlastRemoved).total_seconds(), tmax))
                        print("3.deki değiştirmeden önceki timeout" ,idle_timeout)
                        print("çıkarmadan 2.si", (tpacketIn - tlastRemoved).total_seconds())
                        if idle_timeout <  1:
                            idle_timeout = 1
                        print("3. print %s t_last_duration: %d tpacketIn: %s tlastRemoved: %s idle timeout: " % (key, tlastDuration, tpacketIn ,tlastRemoved), idle_timeout)
                       
                else:
                    if int(tlastDuration) > 0: 
                        idle_timeout = int(tlastDuration)
                        print("4. print %s t_lastduration: %d" % (key, tlastDuration), idle_timeout)
                    else:
                        idle_timeout = 1
                        print("5. print %s" % (key), idle_timeout)
            elif table_occupancy > 0.95:
                idle_timeout = 1
                print("6. print %s" % (key), idle_timeout)
            
       
       
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
        

    #send stats request every 10s
    def _monitor(self):
        global rejected_flows
        global table_occupancy
        global total_packet_in_count
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
               
                #self.remove_flow(dp, 2)
                self.send_table_stats_request(dp)
                self.send_meter_stats_request(dp)
                #self.check_and_delete_entries() #sonra aç
                #print("Data table: ", self.display_data_table())
                self.display_data_table()
                #self.calculate_heuristic()
                print("DATA TABLE FOR PROACTIVE", self.display_eviction_data_table())
                print("REJECTED FLOWS", rejected_flows)
                #print("FLOW TABLE", self.flow_table)
                print("TOTAL PACKET COUNT", total_packet_in_count)
                print("TABLE OCCUPANCY", table_occupancy)
                
            
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
    
    '''
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        table = PrettyTable()
        table.field_names = ["Table ID", "Duration (Sec)", "Priority", "Idle Timeout", "Hard Timeout", "Cookie", "Packet Count", "Byte Count", "Match", "Instructions"]

        for stat in ev.msg.body:
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

        self.logger.info('FlowStats:\n' + table.get_string())
        #self.logger.info('datapath         '
        #                'in-port  eth-dst           '
        #                'out-port packets  bytes')
        #self.logger.info('---------------- '
        #                '-------- ----------------- '
        #               '-------- -------- --------')
        
        

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

      
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    '''

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.send_flow_stats_request(datapath)
        #print("hello world!")


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
        global totalNUmFLows
        global total_packet_in_count
        with totalNumFlows_lock:
          
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
                existing_flow_attributes['last_packet_in'] = current_time
                self.data_table[key] = existing_flow_attributes
                
                allocatedTimeout = self.set_idle_timeout(key)
                totalNUmFLows += 1 #increase the number of flows since I'm adding to flow table
                self.flow_table.add(key)
                
                if key in self.eviction_data_table:
                    self.eviction_data_table[key]["packet_in_time"] = current_time
                    self.eviction_data_table[key]["hit_count"] = 0
                else:
                    self.eviction_data_table.setdefault(key, {})["packet_in_time"] = current_time
                    self.eviction_data_table[key]["hit_count"] = 0
                    
                
                
                if key in self.data_table:
                    packet_count = self.data_table.get(key).get("packet_count", 0)
                    packet_count += 1
                    self.data_table[key]["packet_count"] = packet_count
                    
                    
                else:
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
                self.data_table[key]["idle_timeout"] = allocatedTimeout
                #print("arttırıldı", key)
                #self.eviction_data_table[key]["packet_count"] = packet_count
            else:
                self.data_table[key] = {"idle_timeout": allocatedTimeout}  # Initialize packet_count as 1 for the new key
            
            
            
          
               
                
               
                #print("FLOW TABLEEEE", self.flow_table)
              
                
            '''
            else: # flow is in already flow table, increase the hit count
                if key in self.eviction_data_table:
                    hit_count = self.eviction_data_table.get(key).get("hit_count", 0)
                    hit_count += 1
                    self.eviction_data_table[key]["hit_count"] = hit_count
                else:
                    self.eviction_data_table.setdefault(key, {})["hit_count"] = 1
            '''

            #last_hit_time field update regardless of being in flow table
            if key not in self.eviction_data_table:
                # If the key doesn't exist, set the value for the key using setdefault
                self.eviction_data_table.setdefault(key, {})["idle_timeout"] = allocatedTimeout
                
                #self.eviction_data_table[key]["last_hit_time"] = current_time 
            else:
                # If the key exists, update the value
                self.eviction_data_table[key]["idle_timeout"] = allocatedTimeout
                #self.eviction_data_table[key]["last_hit_time"] = current_time 
           
                
            
            
            # Get the existing flow attributes (assuming you have access to flow-specific identifier, e.g., cookie)
        
            #existing_flow_attributes = self.data_table.get(key, {})

            # Get the current time in a suitable format
            #current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            # Update only the last_packet_in attribute, preserving other attributes
            #existing_flow_attributes['last_packet_in'] = current_time
            
            #self.eviction_data_table[key]["packet_in_time"] = current_time
            #this is the first last_hit_time
            # Update the flow table with the modified flow attributes
            #self.data_table[key] = existing_flow_attributes
                    
            datapath.send_msg(mod)
            total_packet_in_count += 1
           

    def remove_flow(self, datapath, cookie):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod= parser.OFPFlowMod(
            datapath=datapath,
            cookie=2,
            cookie_mask=0xFFFFFFFFFFFFFFFF,
            table_id=ofproto.OFPTT_ALL,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY
        )
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
                if totalNUmFLows < table_size:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                #if there is another packet come in of the flow that is already in the flow table, allow
                elif key in self.flow_table:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                elif key not in self.flow_table: #check this condition??
                    rejected_flows += 1
                return
            else:
                if totalNUmFLows < table_size:
                    self.add_flow(datapath, 1, match, actions)
                elif key in self.flow_table:
                    self.add_flow(datapath, 1, match, actions)
                elif key not in self.flow_table:
                    rejected_flows += 1

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
        '''
        key = self.generate_key(src, dst, in_port)
        
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        if key in self.eviction_data_table:
            if "packet_in_time" in self.eviction_data_table[key]: 
                # increase hit count while in the table
                #hit_count = self.eviction_data_table.get(key).get("hit_count", 0)
                #hit_count += 1
                #self.eviction_data_table[key]["hit_count"] = hit_count
                self.eviction_data_table[key]["last_hit_time"] = current_time
                #print("LAST HIT CURRENT TIME", current_time)
        '''        
                
           
       
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        
      
            
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
                        self.eviction_data_table[key]["hit_count"] = stat.packet_count
                    else:
                        self.eviction_data_table.setdefault(key, {})["hit_count"] = stat.packet_count
                #print(eth_src)
                #print(eth_dst)
            
            #self.logger.info('FlowStats:\n' + table.get_string())
        print('FlowStats:\n' + table.get_string())
        self.calculate_heuristic()
        #print("DATA TABLE FOR PROACTIVE", self.display_eviction_data_table())
                

        '''
            # Extracting in_port
            in_port_start = stat.match.find("'in_port': ") + len("'in_port': ")
            in_port_end = stat.match.find(",", in_port_start)
            in_port = stat.match[in_port_start:in_port_end]

            # Extracting eth_src
            eth_src_start = stat.match.find("'eth_src': '") + len("'eth_src': '")
            eth_src_end = stat.match.find("'", eth_src_start)
            eth_src = stat.match[eth_src_start:eth_src_end]

            # Extracting eth_dst
            eth_dst_start = stat.match.find("'eth_dst': '") + len("'eth_dst': '")
            eth_dst_end = stat.match.find("'", eth_dst_start)
            eth_dst = match_str[eth_dst_start:eth_dst_end]
            if in_port is not None and dst is not None and src is not None:
                key = self.generate_key(src,dst,in_port)
                self.eviction_data_table[key]["hit_count"] = stat.packet_count
        '''
            
            
        #self.logger.debug('FlowStats: %s', flows)
        #print('FlowStats: %s' % flows)
        
        
        
        
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        global totalNUmFLows
        with totalNumFlows_lock:
            
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
            print(msg.cookie, msg.priority, reason, msg.table_id,
                msg.duration_sec, msg.duration_nsec,
                msg.idle_timeout, msg.hard_timeout,
                msg.packet_count, msg.byte_count, msg.match)
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
            self.data_table[key] = existing_flow_attributes
            #self.eviction_data_table[key]["hit_count"] = 0 #update the hit count to 0 when flow is removed.   
            totalNUmFLows -= 1
            self.flow_table.discard(key)
            
            #delete the key from the eviction data table
            if key in self.eviction_data_table:
                del self.eviction_data_table[key]
            
            if key in self.eviction_cache:
                del self.eviction_cache[key]
            
            #print("AZALTTIM")
    
    def send_meter_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPMeterStatsRequest(datapath, 0, ofp.OFPM_ALL)
        datapath.send_msg(req)
        
    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_reply_handler(self, ev):
        meters = []
        for stat in ev.msg.body:
            meters.append('meter_id=0x%08x len=%d flow_count=%d '
                        'packet_in_count=%d byte_in_count=%d '
                        'duration_sec=%d duration_nsec=%d '
                        'band_stats=%s' %
                        (stat.meter_id, stat.len, stat.flow_count,
                        stat.packet_in_count, stat.byte_in_count,
                        stat.duration_sec, stat.duration_nsec,
                        stat.band_stats))
        self.logger.debug('MeterStats: %s', meters)
        print('MeterStats: %s', meters)




    def send_table_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPTableStatsRequest(datapath, 0)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
    def table_stats_reply_handler(self, ev):
        tables = []
        for stat in ev.msg.body:
            tables.append('table_id=%d active_count=%d lookup_count=%d '
                        ' matched_count=%d' %
                        (stat.table_id, stat.active_count,
                        stat.lookup_count, stat.matched_count))
            if stat.table_id==0:
                print('TableStats: %s', stat)
                #print("flow table ratio: %s" % (stat.active_count/table_size*100))
                #table_occupancy = (stat.active_count/table_size*100)
        
        self.logger.debug('TableStats: %s', tables)
        
    