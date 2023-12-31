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
from prettytable import PrettyTable
import hashlib
from datetime import datetime, timedelta
import logging

#added for stats request
from ryu.lib import hub


#python related library for organizing data?
from operator import attrgetter
import threading

# Initialize a lock
totalNumFlows_lock = threading.Lock()



cookie=0
table_size=5  #just reading
#npacketIn=0
totalNUmFLows=  1 #table miss flow ---- more than one function writes --> mutex?
table_occupancy=1/table_size #only one function writes and others read so this is ok

@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
def print_data_table(data):
    # Create a PrettyTable
    table = PrettyTable()
    table.field_names = ['Key', 'Last Packet In', 'Last Removed', 'Last Duration', '# of Packets']

    # Populate the table with data
    for switch, switch_data in data.items():
        last_packet_in = switch_data.get('last_packet_in', 'N/A')
        last_removed = switch_data.get('last_removed', 'N/A')
        last_duration = switch_data.get('last_duration', 'N/A')
        packet_count = switch_data.get('packet_count', 'N/A')
       
        table.add_row([switch, last_packet_in, last_removed, last_duration, packet_count])
    self.logger.info(table)



@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
def print_proactive_data_table(data):
    # Create a PrettyTable
    table = PrettyTable()
    table.field_names = ['Key', 'Packet In Time', 'Last Hit Time','Idle Timeout', 'Hit Count']

    # Populate the table with data
    for switch, switch_data in data.items():

        packet_in_time = switch_data.get('packet_in_time', 'N/A')
        last_hit_time = switch_data.get('last_hit_time', 'N/A')
        idle_timeout = switch_data.get('idle_timeout', 'N/A')
        hit_count = switch_data.get('hit_count', 'N/A')
       
        table.add_row([switch, packet_in_time, last_hit_time, idle_timeout, hit_count])
    self.logger.info(table)

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
        
        log_file = 'log.txt'
        file_handler = logging.FileHandler(log_file, mode='w') 
        file_handler.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)
       
        
    #calculate heuristic
    def calculate_heuristic(self):
        for key in self.eviction_data_table:
            packet_in = datetime.strptime(self.eviction_data_table[key]["packet_in_time"], "%Y-%m-%d %H:%M:%S")
            last_hit = datetime.strptime(self.eviction_data_table[key]["last_hit_time"], "%Y-%m-%d %H:%M:%S")
            total_hits = 0
            if self.eviction_data_table[key].get("hit_count"):
                total_hits = self.eviction_data_table[key]["hit_count"]
            current_time = datetime.now()
            heuristic = ((last_hit - packet_in).total_seconds()/(current_time-packet_in).total_seconds())* total_hits
            self.eviction_cache[key] = heuristic
        self.logger.info("SELF EVICTION CACHE" , self.eviction_cache)
  
    
     
    #get the table_occupancy globally
    def set_idle_timeout(self, key):
        global table_occupancy
        global totalNUmFLows
        global table_size
        t_init = 1  # Initial value for idle time
        idle_timeout = t_init
        tmax = 30  # Maximum idle time
        
        #table_occupancy=totalNUmFLows/table_size
        #print("TABLE OCCUPANCY IS %f" % (table_occupancy))
        self.logger.info("TABLE OCCUPANCY IS %f ALTERNATIVE METHOD" % (table_occupancy))
        #table_occupancy=totalNUmFLows/table_size
        
        DeleteThreshold = 90 #for deleting flows from data table
        coef95 = 0.9
        b_value = 1
        
        if key not in self.data_table:
            idle_timeout = t_init  # Initialize idle time
            npacketIn = 1
        else:
            tlastDuration = self.data_table.get(key).get('last_duration', 0)
            
            
                
            npacketIn = self.data_table.get(key).get('packet_count', 0)
            #npacketIn += 1
            self.logger.info("N_PACKET_IN FOR THE FLOW %s IS %d" % (key, npacketIn))
 
            if table_occupancy <=  0.75:
                idle_timeout = min(t_init * 2 ** npacketIn, tmax)
            elif table_occupancy <= 0.95:
                tmax = tmax * coef95 - b_value
                tpacketIn = self.data_table.get(key).get('last_packet_in', 0)
                tlastRemoved = self.data_table.get(key).get('last_removed', 0)
                if tpacketIn - tlastRemoved <= tlastDuration:
                    idle_timeout = min(tlastDuration + tpacketIn - tlastRemoved, tmax)
                else:
                    idle_timeout = tlastDuration
            elif table_occupancy > 0.95:
                idle_timeout = 1
            
    
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

        return combined_values

    # This function checks and removes entries from the data table
    def check_and_delete_entries(self):
        current_time = datetime.now()
        elapsed_time = (current_time - self.start_time).total_seconds()

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
            self.logger.info("%s DELETED FROM DATA TABLE" % (key))
     
            del self.data_table[key]
        

    #send stats request every 10s
    def _monitor(self):
        i=0
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
                #self.remove_flow(dp, 2)
                self.send_table_stats_request(dp)
                self.check_and_delete_entries()
                print_data_table(self.data_table)
                print_proactive_data_table(self.eviction_data_table)
              
                #self.calculate_heuristic()
            print(i, table_occupancy)
            i+=1
            hub.sleep(20)


    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        #req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        #datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        
        

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

        
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)

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
        global totalNUmFLows
        with totalNumFlows_lock:
            totalNUmFLows += 1 #increase the number of flows since I'm adding to flow table
            #print("ARTTIRDIM")
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
            
            allocatedTimeout = self.set_idle_timeout(key)
            self.logger.info("ALLOCATED TIMEOUT FOR THE FLOW %s IS %d" % (key, allocatedTimeout))
       
            if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        idle_timeout=allocatedTimeout, hard_timeout=0, priority=priority, match=match,
                                        instructions=inst, flags= flags)
                
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        idle_timeout=allocatedTimeout, hard_timeout=0, match=match, instructions=inst, flags= flags)
            #cookie +=1
            
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
            if key in self.data_table:
                packet_count = self.data_table.get(key).get("packet_count", 0)
                packet_count += 1
                self.data_table[key]["packet_count"] = packet_count
                #print("arttırıldı", key)
                #self.eviction_data_table[key]["packet_count"] = packet_count
            else:
                self.data_table[key] = {"packet_count": 1}  # Initialize packet_count as 1 for the new key
                #self.eviction_data_table[key] = {"packet_count": 1}
                #self.eviction_data_table[key] = {"hit_count": 1}
            
          
            #idle_timeout of the flow for proactive eviction data table
            if key not in self.eviction_data_table:
                # If the key doesn't exist, set the value for the key using setdefault
                self.eviction_data_table.setdefault(key, {})["idle_timeout"] = allocatedTimeout
            else:
                # If the key exists, update the value
                self.eviction_data_table[key]["idle_timeout"] = allocatedTimeout
           
                
            
            
            # Get the existing flow attributes (assuming you have access to flow-specific identifier, e.g., cookie)
        
            existing_flow_attributes = self.data_table.get(key, {})

            # Get the current time in a suitable format
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            # Update only the last_packet_in attribute, preserving other attributes
            existing_flow_attributes['last_packet_in'] = current_time
            
            self.eviction_data_table[key]["packet_in_time"] = current_time
            self.eviction_data_table[key]["last_hit_time"] = current_time #this is the first last_hit_time
            # Update the flow table with the modified flow attributes
            self.data_table[key] = existing_flow_attributes
                    
            datapath.send_msg(mod)

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
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
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
            #print(type(stat.match))
            if 'in_port' in stat.match and 'eth_src' in stat.match and 'eth_dst' in stat.match:
                in_port = stat.match['in_port']
                eth_src = stat.match['eth_src']
                eth_dst = stat.match['eth_dst']
                #print(in_port)
                key = self.generate_key(eth_src,eth_dst,in_port)
                self.eviction_data_table[key]["hit_count"] = stat.packet_count
                #print(eth_src)
                #print(eth_dst)
            
                

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
            
            
            
            
        self.logger.debug('FlowStats: %s', flows)
        print('FlowStats: %s' % flows)
        
        
        
        
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
            #cookie = msg.cookie  # Assuming cookie is unique for each flow

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
            totalNUmFLows -= 1
            #print("AZALTTIM")
    


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
                print("flow table ratio: %s" % (stat.active_count/table_size*100))
                table_occupancy = (stat.active_count/table_size*100)
        
        self.logger.debug('TableStats: %s', tables)

    