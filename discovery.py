from pox.core import core
from pox.lib.revent import *
from pox.lib.recoco import Timer
import pox.openflow.libopenflow_01 as of
import networkx as nx
import matplotlib.pyplot as plt
import time
from scapy.all import *

log = core.getLogger()

class Discovery( EventMixin ):

    def __init__(self):
        # networkx representation of the topology
        self.topo = nx.Graph()
        # list of switches already scheduled w/sendLLDP
        self.scheduled_switches = []
        # send lldp every ldp ttl seconds
        self.lldp_ttl = 1
        core.openflow.addListeners(self)


    def _handle_ConnectionUp(self, event):
        # install flow for all LLDP packets forward to controller
        msg = of.ofp_flow_mod()
        # LLDP Ether type
        msg.match.dl_type = 0x88cc
        # LLDP dest addr '01:80:c2:00:00:0e'
        msg.match.dl_dst = '\x01\x80\xc2\x00\x00\x0e'
        # LLDPs to controller
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        event.connection.send(msg)
        log.debug('LLDP flow configuration sent. Switch: %s' % event.dpid)
        # if dpid no scheduled, then do it!
        if not event.dpid in self.scheduled_switches:
            Timer(self.lldp_ttl, self.send_LLDP, args = [event], recurring = True)
            self.scheduled_switches.append(event.dpid)


    def _handle_ConnectionDown(self, event):
        #XXX delete switch from list of scheduled switch
        log.debug("Switch %s is DOWN" % event.dpid)


    def _handle_PortStatus(self, event):
        #XXX what to do in case of ports going down/up
        pass


    def _handle_PacketIn(self, event):
        """rocess incoming packets."""
        # scapy-fy packet
        pkt = Ether(event.data)

        # if pkt is LLDP then use it to manage topology view 
        if pkt.type == 0x88cc: 
            self.manage_topology(pkt, event.dpid, event.port)
        

    def manage_topology(self, pkt, d_dpid, d_port):
        """Creates/Updates the topology acording to what it "hears" from LLDP"""
        # is it a well formed LLDP packet?
        if pkt.type == 0x88cc and \
            LLDPChassisId in pkt and \
            LLDPPortId in pkt and \
            LLDPTTL in pkt and \
            LLDPDUEnd in pkt:
               # comodity/documentation variables
               s_dpid = int(pkt['LLDPChassisId'].value)
               s_port = int(pkt['LLDPPortId'].value)
               # if no data, return
               if not (s_dpid or s_port):
                   log.debug('Got Invalid LLDP packet')
                   return
               #log.debug('Got LLDP packet [Switch: %s Port %s] from switch %s port %s' \

               # 1) if "seen" nodes are new, add them to the topology view
               if not s_dpid in self.topo:
                   self.topo.add_node(s_dpid, {'ports':[]} )
               if not d_dpid in self.topo:
                   self.topo.add_node(d_dpid, {'ports':[]} )
               # 1.1) while we are on it, keep track of which ports are being used by source dpid
               if not s_port in self.topo.node[s_dpid]['ports']:
                   self.topo.node[s_dpid]['ports'].append(s_port)
               # 1.2) and keep track of destination dpid's used ports
               if not d_port in self.topo.node[d_dpid]['ports']:
                   self.topo.node[d_dpid]['ports'].append(d_port)
               # 2) add new edge to topology view, timestamp the new edge
               if not((s_dpid, d_dpid) in self.topo.edges() or (d_dpid, s_dpid) in self.topo.edges()):
                   self.topo.add_edge(s_dpid, d_dpid, {'time_stamp':time.time(),'s_port':s_port,'d_port':d_port})
               # 2.1) if it is an existing edge, refresh the timestamp...edge is still alive
               else:
                   self.topo.edge[s_dpid][d_dpid]['time_stamp'] = time.time()


    def send_LLDP(self, event):
        """creates a LLDP packet and sends it through all dpid's ports.
        This packet is sent through all of dpid's ports every 
        self.lldp_ttl seconds"""
        # note-to-self: event.ofp is of ofp_features_reply type
        # note-to-self: event.ofp.ports has all the ports defined in this dpid
        # LLDP destination address
        dst = '01:80:c2:00:00:0e'
        # LLDP ethertype
        type = 0x88cc
        # note-to-self: ofp.ports == all ports in the dpid
        for p in event.ofp.ports:
            if p.port_no < of.OFPP_MAX:
                chassis_id = event.dpid
                src = str(p.hw_addr)
                port = p.port_no
                lldp_p = Ether(src = src, dst = dst, type = type)/\
                        LLDPChassisId(subtype = 7, macaddr = '00:00:ca:fe:ba:be', value = chassis_id)/\
                        LLDPPortId(subtype = 7, macaddr = src, value = port)/\
                        LLDPTTL(seconds = self.lldp_ttl)/\
                        LLDPDUEnd()
                #log.debug("dpid: %d port_no: %s hw_addr: %s" % (event.dpid, p.port_no, p.hw_addr))
                # send LLDP packet
                pkt = of.ofp_packet_out(action = of.ofp_action_output(port = port))
                pkt.data = bytes(lldp_p)
                event.connection.send(pkt)

    def graph(self):
        """
        Draws the current view of the topology. No hosts, just switches
        """
        pos = nx.circular_layout(self.topo)
        nx.draw(self.topo, pos)
        edge_labels = dict([((u,v),str(d['s_port'])+'-'+str(d['d_port'])) for u,v,d in self.topo.edges(data=True)])
        nx.draw_networkx_edge_labels(self.topo, pos, edge_labels)
        plt.show()


def launch():
    core.register('discovery', Discovery())
    log.debug('Discovery registered')
