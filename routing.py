# from pox
from pox.core import core
from pox.lib.revent import *
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of
# from me 
from util import *
# from third parties
import networkx as nx
from scapy.all import Ether, IP, ICMP, TCP, UDP


log = core.getLogger()

class Routing( EventMixin ):

    # XXX listen to portstatus and modify routing of port status changes?

    def __init__(self):
        # listen to all events from core
        core.openflow.addListeners(self)

    def _handle_PacketIn(self, event):

        # scapy-fy packet
        pkt = Ether(event.data)


        # if packet not IP then nothing to see here, move along
        if not pkt[Ether].type == 0x0800:
            return
        # we do have an IP ethertype, but do we really have an ip packet?
        if not IP in pkt:
            return

        # TODO security check for policy component and validate if packet is
        # allowed. because we are only accepting IP packets, policy rules are
        # only L3 and above

        # "documentation" variables
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        log.debug('ROUTING: Got ip packet: %s -> %s' % (src_ip, dst_ip))

        # where is src located? 
        (src_dpid, src_port) = find_dpid_port_by_ip(src_ip)
        if not src_dpid or not src_port:
            log.error('ROUTING: Could not find switch/port hosting src ip %s' % src_ip)
            return

        # where is dst located?
        (dst_dpid, dst_port) = find_dpid_port_by_ip(dst_ip)
        if not dst_dpid or not dst_port:
            log.error('ROUTING: Could not find switch/port hosting dst ip %s' % dst_ip)
            return

        log.debug('ROUTING: Routing from %s (%s,%s) to %s (%s,%s)' % \
                 (src_ip, src_dpid, src_port, dst_ip, dst_dpid, dst_port))

        # get path (node list - {n1,p1,n2,p2}) from src to dst
        path = self.get_path(src_dpid, dst_dpid)
        if not path:
            log.error('ROUTING: There is no path between %s and %s' % (src_ip, dst_ip))
            return

        log.debug('ROUTING: From %s to %s take path %s' % (src_ip, dst_ip, path))

        # install flows from src to dst (match srcip, dstip) and from dst to
        # src (bidir)
        result = self.install_flows(pkt, path)

        # XXX TODO: losing first packet after installing flow...have to resend
        # packet that triggered this PacketIn (how?)



    def get_path(self, src_dpid, dst_dpid):
        """
        Main routing algorithm for finding a path from src node to dst node.
        "path" is a list of networkx nodes joining src_ip to dst_ip
        """
        #XXX path is calculated on the slow path. if there are any changes
        #XXX after path-calculation bad things could happen. Have to fix this

        # before expending any cycles, do we have a path from src dpid to dst
        # dpid?
        if not nx.has_path(core.discovery.topo, src_dpid, dst_dpid):
            return None

        # this is a very "lazy" algorithm implementing shortest_path, other
        # options are welcomed. NOTE: at the end of the day, the calculated
        # path from src_ip to dst_ip is also a policy/security/function
        # decision. this functions returns a networkx list of nodes connecting
        # src_dpid and dst_dpid (both ends included in the list). 'p' is a
        # networkx list of nodes
        # XXX test, manual path definition
        if src_dpid == 5 and dst_dpid == 2:
            p = [5,4,1,3,2]
        else:
            p = nx.shortest_path(core.discovery.topo, src_dpid, dst_dpid)

        # now that we have a list of nodes, we have to find the ports joining
        # them. at the end of the loop, path will be a list of of dict
        # {n1,p1,n2,p2} where source node (n1) port p1 connects to destination
        # node (n2) port p2
        path = []
        n1 = p.pop(0)
        for n2 in p:
            (p1, p2) = get_linking_ports(core.discovery.topo, n1,n2)
            if not p1 or not p2:
                return None
            path.append(dict(n1=n1,p1=p1,n2=n2,p2=p2))
            n1 = n2
        # path is a list of {n1,p1,n2,p2}
        return path


    def install_flows(self, pkt, path):
        """
        Install flows on the switch according to path. Expects path to be a
        list of {n1,p1,n2,p2}. Returns True if no issues, otherwise False
        """
        # XXX have to fix situation where path may get broken because of links going down

        # XXX do we have to book-keep which flows were installed in which dpid? 

        if not IP in pkt:
            log.error('ROUTING: Installing flow, but no IP packet to match in egress witch')
            return False

        # how long shoud flows be "active" at the switch?
        ROUTING_FLOW_IDLE_TIMEOUT = 15

        # "documentation/convenience" variable
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # ------> install flows (direction from n1 to n2)
        for n in path:
            # get connection object from dpid (source node)
            conn = core.openflow.getConnection(n['n1'])
            if not conn:
                log.error('ROUTING: Could not get connection from switch %s' % n['n1'])
                return False
            # create flow_mod message
            msg = of.ofp_flow_mod()
            msg.idle_timeout = ROUTING_FLOW_IDLE_TIMEOUT
            msg.match.dl_type = 0x0800
            msg.match.nw_dst = dst_ip
            msg.actions.append(of.ofp_action_output(port=n['p1']))
            # XXX does conn.send returns an error if failed?
            # XXX time for a barrier_request?
            conn.send(msg)

        # src -> dst egress port from egress node comes from gmat
        (egress_dpid, egress_port) = find_dpid_port_by_ip(dst_ip)
        if not egress_dpid or not egress_port:
            log.error('ROUTING: Could not locate egress switch/port')
            return False
        conn = core.openflow.getConnection(egress_dpid)
        if not conn:
            log.error('ROUTING: Could not get connection from egress switch %s' % egress_dpid)
            return False
        msg = of.ofp_flow_mod()
        msg.idle_timeout = ROUTING_FLOW_IDLE_TIMEOUT
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = dst_ip
        msg.actions.append(of.ofp_action_output(port=egress_port))
        # XXX does conn.send returns an error if failed?
        # XXX time for a barrier_request?
        conn.send(msg)

        # <------ install flow (direction from n2 to n1)
        for n in path:
            conn = core.openflow.getConnection(n['n2'])
            if not conn:
                log.error('ROUTING: Could not get connection from switch %s' % n['n2'])
                return False
            # create flow_mod message
            msg = of.ofp_flow_mod()
            msg.idle_timeout = ROUTING_FLOW_IDLE_TIMEOUT
            msg.match.dl_type = 0x0800
            msg.match.nw_dst = src_ip
            msg.actions.append(of.ofp_action_output(port=n['p2']))
            # XXX does conn.send returns an error if failed?
            # XXX time for a barrier_request?
            conn.send(msg)

        # dst -> src egress port from egress node comes from gmat
        (egress_dpid, egress_port) = find_dpid_port_by_ip(src_ip)
        if not egress_dpid or not egress_port:
            log.error('ROUTING: Could not locate egress switch/port')
            return False
        conn = core.openflow.getConnection(egress_dpid)
        if not conn:
            log.error('ROUTING: Could not get connection from egress switch %s' % egress_dpid)
            return False
        msg = of.ofp_flow_mod()
        msg.idle_timeout = ROUTING_FLOW_IDLE_TIMEOUT
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = src_ip
        msg.actions.append(of.ofp_action_output(port=egress_port))
        # XXX does conn.send returns an error if failed?
        # XXX time for a barrier_request?
        conn.send(msg)

        # so far so good
        return True


def launch():
    # discovery and arp_response are necessary components for routing
    if core.hasComponent('discovery') and core.hasComponent('arp_response'):
        component = Routing()
        core.register('routing', component)
        log.debug('ROUTING: Routing registered')
    else:
        log.error('ROUTING: Routing component *not* loaded. Required components missing')
