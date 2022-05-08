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

# LABORATORY OF NETWORK PROGRAMMABILITY AND AUTOMATION
# 2021
# by Franco Callegati and Chiara Contoli
#
# This modified simple switch controller implements a simple firewall
# it is intended to be used with the mininet topology with 1 switch 3 hosts and 1 controller
# traffic from host1 to host2 is allowed 
# traffic from host2 to host3 is allowed
# traffic from host1 to host3 is NOT allowed
# 


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.ofproto import inet
from ryu.lib.packet import tcp


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # List of gateways to be handled by the controller
        self.gateways = []
        self.gateways.append("10.0.1.254")
        self.gateways.append("10.0.2.254")
        self.gateways_MAC = []
        self.gateways_MAC.append("00:00:00:11:11:11")
        self.gateways_MAC.append("00:00:00:22:22:22")
        
        # ARP table at the controller level to manage gateways
        self.arp_table_gw={}
        self.arp_table_gw["10.0.1.254"] = "00:00:00:11:11:11"
        self.arp_table_gw["10.0.2.254"] = "00:00:00:22:22:22"

        self.host_IP_to_MAC = {}
        self.host_IP_to_MAC["10.0.2.2"] = "86:46:ec:8d:1f:fd"
        self.host_IP_to_MAC["10.0.1.1"] = "42:3d:5a:8f:76:0f"


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        self.logger.info("SWITCH FEATURES - CONFIG_DISPATCHER PHASE")
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
#        match = parser.OFPMatch(eth_type=0x0806,eth_dst='ff:ff:ff:ff:ff:ff')
#        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
#        self.add_flow(datapath, 1, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
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
        #self.logger.info("In port %d", in_port) 

        pkt = packet.Packet(msg.data)
        # parse ethernet packet
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in DPID=%s MAC_SRC=%s MAC_DST=%s IN_PORT=%s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        self.logger.info("DISCOVERED MAC %s at PORT %s on DPID %s", src, in_port, dpid)

        # set output port for known MAC destinations
        # this will be used depending on the following logics
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            self.logger.info("KNOWN destination MAC %s has OUT_PORT %s", dst, out_port)
        else:
            out_port = ofproto.OFPP_FLOOD
            self.logger.info("UNKNOWN destination MAC %s pkt is FLOODED %s", dst, out_port)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info("ARP PACKET RECEIVED")
            arp_pkt = pkt.get_protocol(arp.arp)
            # ARP request
            if arp_pkt.opcode == arp.ARP_REQUEST:
                target_ip = arp_pkt.dst_ip
                if target_ip in self.gateways:
                    self.logger.info("ARP REQUEST for GW %s RECEIVED", target_ip)
                    # Controller has to send and ARP reply, acting as the gateway
                    # obtain the MAC of dst IP  (in this case, GW_MAC - inderect delivery)
                    eth_pkt = pkt.get_protocol(ethernet.ethernet)
                    arp_resolv_mac = self.arp_table_gw[arp_pkt.dst_ip]
                    ether_hd = ethernet.ethernet(dst = eth_pkt.src, 
                                src = arp_resolv_mac, 
                                ethertype = ether_types.ETH_TYPE_ARP)
                    arp_hd = arp.arp(hwtype=1, proto = 2048, hlen = 6, plen = 4,
                         opcode = arp.ARP_REPLY, src_mac = arp_resolv_mac, 
                         src_ip = arp_pkt.dst_ip, dst_mac = eth_pkt.src,
                         dst_ip = arp_pkt.src_ip)
                    arp_reply = packet.Packet()
                    arp_reply.add_protocol(ether_hd)
                    arp_reply.add_protocol(arp_hd)
                    arp_reply.serialize()
                    # send the Packet Out mst to back to the host who is initilaizing the ARP
                    actions = [parser.OFPActionOutput(in_port)]
                    out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, 
                                  ofproto.OFPP_CONTROLLER, actions,
                                  arp_reply.data)
                    datapath.send_msg(out)
                else:
                    self.logger.info("ARP REQUEST for host %s RECEIVED: direct delivery, out_port:%s", target_ip, out_port)
                    actions = [parser.OFPActionOutput(out_port)]
                    # install a flow to avoid packet_in next time
                    if out_port != ofproto.OFPP_FLOOD:
                        match = parser.OFPMatch(in_port=in_port, eth_type=0x0806, eth_dst=dst, eth_src=src)
                        self.add_flow(datapath, 1, match, actions)
                    else:
                        data = None
                        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                            data = msg.data

                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)
            # ARP reply
            elif arp_pkt.opcode == arp.ARP_REPLY:
                target_ip = arp_pkt.dst_ip
                if target_ip in self.gateways:
                    # in this case we assume indirect delivery
                    self.logger.info("ARP REPLY for GW %s RECEIVED", target_ip)
                    # Controller has to install flow rule
                    match = parser.OFPMatch(eth_type=0x0800, ip_proto=inet.IPPROTO_ICMP,ipv4_dst=arp_pkt.src_ip)
                    actions = []
                    actions.append( parser.OFPActionSetField(eth_src=arp_pkt.dst_mac) )
                    actions.append( parser.OFPActionSetField(eth_dst=arp_pkt.src_mac) )
                    actions.append(parser.OFPActionOutput(in_port))
                    self.add_flow(datapath, 1, match, actions)
                    self.logger.info("FLOW RULE TO FWD ICMP TO DESTINATION INSTALLED")
                else:    
                    #direct delivery
                    self.logger.info("ARP REPLY for host %s RECEIVED, out_port %s: direct delivery", target_ip, out_port)
                    actions = [parser.OFPActionOutput(out_port)]
                    # install a flow to avoid packet_in next time
                    if out_port != ofproto.OFPP_FLOOD:
                        match = parser.OFPMatch(in_port=in_port, eth_type=0x0806, eth_dst=dst, eth_src=src)
                        self.add_flow(datapath, 1, match, actions)
                    else:
                        data = None
                        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                            data = msg.data

                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)

	    # logics to deal with IP packets
        # if ethernet carries IP parses the IP packet           
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            self.logger.info("Incoming IP packet inside Ethernet")
            # if IP carries TCP parses the TCP packet
            if ip_pkt.proto == inet.IPPROTO_ICMP:
                self.logger.info("ICMP packet received")
                # check if pkt is an ICMP req destinated to MAC_GW
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST and dst in self.gateways_MAC and ip_pkt.dst not in self.gateways:
                    self.logger.info("ECHO REQUEST to GW: indirect delivery!")
                    # if destination is known, install flow rule to forward echo request to real destination
                    # else, send an ARP request for real destination
                    # Controller has to install flow rule
                    match = parser.OFPMatch(eth_type=0x0800, ip_proto=inet.IPPROTO_ICMP, ipv4_dst=ip_pkt.src)
                    actions = []
                    actions.append( parser.OFPActionSetField(eth_src=dst) )
                    actions.append( parser.OFPActionSetField(eth_dst=src) )
                    actions.append(parser.OFPActionOutput(in_port))
                    self.add_flow(datapath, 1, match, actions)
                    self.logger.info("FLOW RULE TO FWD ICMP TO SOURCE INSTALLED")

                    out_port = ofproto.OFPP_FLOOD
                    # Controller has to send and ARP reply, acting as the gateway
                    # obtain the MAC of dst IP  (in this case, GW_MAC - inderect delivery)
                    #ip_gw =  self.arp_table_gw.keys()[self.arp_table_gw.values().index(dst)]
                    ip_gw = list(self.arp_table_gw.keys())[list(self.arp_table_gw.values()).index(dst)]
                    eth_pkt = pkt.get_protocol(ethernet.ethernet)
                    ether_hd = ethernet.ethernet(src = eth_pkt.dst, 
                                ethertype = ether_types.ETH_TYPE_ARP)
                    arp_hd = arp.arp(hwtype=1, proto = 2048, hlen = 6, plen = 4,
                        opcode = arp.ARP_REQUEST, src_mac = eth_pkt.dst, 
                        src_ip = ip_gw,
                        dst_ip = ip_pkt.dst)
                    arp_request = packet.Packet()
                    arp_request.add_protocol(ether_hd)
                    arp_request.add_protocol(arp_hd)
                    arp_request.serialize()
                    # send the Packet Out mst to back to the host who is initilaizing the ARP
                    actions = [parser.OFPActionOutput(out_port)]
                    out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, 
                                ofproto.OFPP_CONTROLLER, actions,
                                arp_request.data)
                    datapath.send_msg(out)
                    self.logger.info("ARP REQUEST FROM GW %s to DST host %s sent", ip_gw, ip_pkt.dst)
                elif icmp_pkt.type == icmp.ICMP_ECHO_REQUEST and dst not in self.gateways_MAC and ip_pkt.dst not in self.gateways:
                    #direct delivery
                    self.logger.info("ECHO REQUEST to host %s: direct delivery!", ip_pkt.dst)
                    actions = [parser.OFPActionOutput(out_port)]
                    # install a flow to avoid packet_in next time
                    if out_port != ofproto.OFPP_FLOOD:
                        match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=inet.IPPROTO_ICMP, eth_dst=dst, ipv4_dst=ip_pkt.dst)
                        self.add_flow(datapath, 1, match, actions)
                    else:
                        data = None
                        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                            data = msg.data

                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)
                elif icmp_pkt.type == icmp.ICMP_ECHO_REPLY and dst not in self.gateways_MAC and ip_pkt.dst not in self.gateways:
                    #direct delivery
                    self.logger.info("ECHO REPLY to host %s: direct delivery!", ip_pkt.dst)
                    actions = [parser.OFPActionOutput(out_port)]
                    # install a flow to avoid packet_in next time
                    if out_port != ofproto.OFPP_FLOOD:
                        match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=inet.IPPROTO_ICMP, eth_dst=dst, ipv4_dst=ip_pkt.dst)
                        self.add_flow(datapath, 1, match, actions)
                    else:
                        data = None
                        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                            data = msg.data

                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)
            if ip_pkt.proto == inet.IPPROTO_UDP:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_UDP)
                actions = []            
                self.logger.info("UDP traffic - DROP")
            if ip_pkt.proto == inet.IPPROTO_TCP:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                tcp_dst = tcp_pkt.dst_port
                self.logger.info("TCP packet with destination port %s", tcp_dst)