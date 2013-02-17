import networkx as nx
from pox.core import core
from pox.lib.revent import *
import pox.openflow.libopenflow_01 as of
from util import find_dpid_port_by_ip

from scapy.all import *


log = core.getLogger()

class Routing( EventMixin ):

    def __init__(self):
        # listen to all events from core
        core.openflow.addListeners(self)

    def _handle_PacketIn(self, event):
        pkt = Ether(event.data)
        # if not IP then nothing to see here, move along
        if not pkt[Ether].type == 0x0800:
            return
        # we do have an IP ethertype, but do we really have an IP packet?
        if not IP in pkt:
            return

        # "documentation" variables
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        log.debug('ROUTING: Got IP packet: %s -> %s' % (src_ip, dst_ip))

        # where is src located? 
        (src_dpid, src_port) = find_dpid_port_by_ip(src_ip)
        if not src_dpid or not src_port:
            log.error('ROUTING: Could not find switch/port hosting src IP %s' % src_ip)
            return
        # where is dst located?
        (dst_dpid, dst_port) = find_dpid_port_by_ip(dst_ip)
        if not dst_dpid or not dst_port:
            log.error('ROUTING: Could not find switch/port hosting dst IP %s' % dst_ip)
            return

        log.debug('ROUTING: Have to route from %s (%s,%s) to %s (%s,%s)' % \
                 (src_ip, src_dpid, src_port, dst_ip, dst_dpid, dst_port))

        # get path to take (node list) to get from src to dst
        src_path = self.get_path(src_dpid, dst_dpid)
        if not src_path:
            log.error('ROUTING: There is no path between %s and %s' % (src_ip, dst_ip))
            return

        # this is one option, another one could be to use the same path from
        # src to dst that from dst to src
        # get path to take (node list) to get from dst to src
        dst_path = self.get_path(dst_dpid, src_dpid)
        if not dst_path:
            log.error('ROUTING: There is no path between %s and %s' % (dst_ip, src_ip))
            return

        log.debug('ROUTING: From %s to %s take path %s' % (src_ip, dst_ip, src_path))
        log.debug('ROUTING: From %s to %s take path %s' % (dst_ip, src_ip, dst_path))

        # install flows from src to dst (match srcip, dstip)
        self.install_flows(event, src_path)

        # install flows from dst to src (match dstip, srcip)
        self.install_flows(event, dst_path)



    def get_path(self, src_dpid, dst_dpid):
        """
        Main routing algorithm for finding a path from src node to dst node.
        "path" is a list of nodes joining src_ip to dst_ip
        """
        # before expending any cycles, do we have a path from src to dst
        if not nx.has_path(core.discovery.topo, src_dpid, dst_dpid):
            return None
        # this is a very basic algorithm implementing shortest_path
        # many other options are welcomed
        return nx.shortest_path(core.discovery.topo, src_dpid, dst_dpid)


    def install_flows(self, event, path):
        """
        install flows on the switch according to path
        """
        pass


def launch():
    if core.hasComponent('arp_response') and core.hasComponent('discovery'):
        component = Routing()
        core.register('routing', component)
        log.debug('ROUTING: Routing registered')
    else:
        log.error('ROUTING: routing component *not* loaded. Required components missing')
