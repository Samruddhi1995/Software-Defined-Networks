from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
import json
# packet

from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp


class shortest_path(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(shortest_path, self).__init__(*args, **kwargs)
        self.arp_table = {}
        self.arp_table = {'10.0.0.1': '00:00:00:00:00:01',
                          '10.0.0.2': '00:00:00:00:00:02'}

    # Initial handshake between switchand controller proactive entries are added to switch here

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser  # parser

        # this code does default match and sends flows that default packet should be send to controller
        match = ofp_parser.OFPMatch()
        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER)])
        inst = [action]
        self.add_flow(dp=dp, match=match, inst=inst, table=0, priority=0)

        # Whenever new TCP flow occur switch forward packet first packet to controller
        dpid = dp.id

        if (dpid == 4):  # Switch four
            self.dp4 = dp
            self.flow_match_layer4(dp, inet.IPPROTO_TCP)

        if (dpid == 5):  # Switch five

            self.dp5 = dp
            self.flow_match_layer4(dp, inet.IPPROTO_TCP)

        if (dpid == 1):  # Switch one

            self.dp1 = dp

        if (dpid == 2):  # Switch two

            self.dp2 = dp

        if (dpid == 3):  # Switch two

            self.dp3 = dp
    # This defination creates a match, action and adds flow to switch

    def flow_match_layer4(self, dp, proto):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=proto)
        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER)])
        inst = [action]
        self.add_flow(dp, match, inst, 0, 10)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # self.logger.info(ev)
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        # get datapath ID to identify OpenFLow Switches
        dpid = dp.id
        # analyse the received packets using packet library to take appropriate action
        pkt = packet.Packet(msg.data)
        #self.logger.info("This is packet in message!")
        #self.logger.info(pkt)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth_pkt.ethertype
        eth_dst = eth_pkt.dst
        eth_src = eth_pkt.src

        in_port = msg.match['in_port']

        # self.logger.info("This is packet_in from switch id %s",dpid)
        # self.logger.info("packet in ether_type = %s dpid = %s, src =  %s, dst =  %s, in_port =  %s ",ethertype, dpid, eth_src, eth_dst, in_port)

        # If arp packet send to handle_arp
        if (ethertype == ether.ETH_TYPE_ARP):
            self.handle_arp(dp, in_port, pkt)

        # If packet is TCP sync from H2 and H4 then Send RST message
        if (ethertype == ether.ETH_TYPE_IP):
            self.logger.info("This is packet in message")
            self.logger.info(pkt)
            self.handle_tcp(dp, pkt)


    # FlowMod for adding proactive flows in to switch

    def add_flow(self, dp, match, inst, table, priority):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        buffer_id = ofp.OFP_NO_BUFFER

        mod = ofp_parser.OFPFlowMod(
            datapath=dp, table_id=table, priority=priority,
            match=match, instructions=inst
        )
        # self.logger.info("Here are flows")
        # self.logger.info(mod)
        dp.send_msg(mod)

    # PacketOut used to send packet from controller to switch

    def send_packet(self, dp, port, pkt):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        pkt.serialize()
        data = pkt.data
        action = [parser.OFPActionOutput(port=port)]

        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=action, data=data)
        dp.send_msg(out)

    # In our case arp table is hardcoded so arprequest is resolved by controller

    def handle_arp(self, dp, port, pkt):
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)

        # checking if it's arp packet return None if not arp packet
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return

        # checking if the destination address exists in arp_table returns NONE otherwise
        if self.arp_table.get(pkt_arp.dst_ip) == None:
            return

        get_mac = self.arp_table[pkt_arp.dst_ip]

        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                ethertype=ether.ETH_TYPE_ARP,
                dst=pkt_ethernet.src,
                src=get_mac
            )
        )

        pkt.add_protocol(
            arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=get_mac,
                src_ip=pkt_arp.dst_ip,
                dst_mac=pkt_arp.src_mac,
                dst_ip=pkt_arp.src_ip
            )
        )

        self.send_packet(dp, port, pkt)


    def add_reactive_flow(self, dp, match, table, priority,out_port):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        buffer_id = ofp.OFP_NO_BUFFER

        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [ofp_parser.OFPActionOutput(out_port)])
        inst = [action]

        mod = ofp_parser.OFPFlowMod(
            datapath=dp, table_id=table, priority=priority,
            match=match, instructions=inst
        )
        # self.logger.info("Here are flows")
        # self.logger.info(mod)
        dp.send_msg(mod)

    # PacketOut used to send packet from controller to switch

    def handle_tcp(self, dp, pkt):
        self.logger.info("handle_tcp was called")
        self.logger.info(pkt)
        #ethernet packet
        eth_pkt = pkt.get_protocol(ethernet.ethernet)


        #ip packet
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        ip_src = ipv4_pkt.src
        ip_dst = ipv4_pkt.dst

        ip_proto = ipv4_pkt.proto  #upper layer protocol will be TCP in our case

        #TCP packet
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        dst_port = tcp_pkt.dst_port
        src_port = tcp_pkt.src_port

        if ip_src == "10.0.0.1" and ip_dst == "10.0.0.2":

            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser
            match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst,ip_proto=ip_proto,tcp_dst=dst_port, tcp_src=src_port)

            self.add_reactive_flow(self.dp4, match, 0, 100, 2)
            self.add_reactive_flow(self.dp1, match, 0, 100, 2)
            self.add_reactive_flow(self.dp5, match, 0, 100, 1)

            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser
            match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_dst, ipv4_dst=ip_src, ip_proto=ip_proto,
                                        tcp_dst=src_port, tcp_src=dst_port)


            self.add_reactive_flow(self.dp4, match, 0, 100, 1)
            self.add_reactive_flow(self.dp1, match, 0, 100, 1)
            self.add_reactive_flow(self.dp5, match, 0, 100, 2)
            self.send_packet(self.dp5,1,pkt)


        if ip_src == "10.0.0.2" and ip_dst == "10.0.0.1":

            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser
            match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst,ip_proto=ip_proto,tcp_dst=dst_port, tcp_src=src_port)

            self.add_reactive_flow(self.dp4, match, 0, 100, 1)
            self.add_reactive_flow(self.dp1, match, 0, 100, 1)
            self.add_reactive_flow(self.dp5, match, 0, 100, 2)

            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser
            match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_dst, ipv4_dst=ip_src, ip_proto=ip_proto,
                                        tcp_dst=src_port, tcp_src=dst_port)


            self.add_reactive_flow(self.dp4, match, 0, 100, 2)
            self.add_reactive_flow(self.dp1, match, 0, 100, 2)
            self.add_reactive_flow(self.dp5, match, 0, 100, 1)
            self.send_packet(dp4, 1, pkt)

