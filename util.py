"""
Copyright (c) 2013, Javier Liendo All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list
of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this
list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

"""
discovery.py node format: (n1, {'link_to':[(p1,n2), (p2, n3), (p3, n4)]})
p1 of n1 links to n2
p2 of n1 links to n3
p3 of n1 links to n4

"""
from pox.core import core

log = core.getLogger()

def get_linking_ports(g, n1, n2):
    """
    returns the ports linking two nodes in g
    returns tuple (p1, p2)
    """
    # XXX this func asumes that there is one and only one port pointing to 
    # XXX one node...this may not be always true
    # p1 is the port from n1 pointing to n2
    # p2 is the port from n2 pointing to n1
    p1 = [p for i, (p,n) in enumerate(g.node[n1]['link_to']) if n == n2]
    p2 = [p for i, (p,n) in enumerate(g.node[n2]['link_to']) if n == n1]
    if not (p1 and p2): 
        return (None, None)
    # XXX ugly...fix comprenhension to not return list
    p1 = p1.pop()
    p2 = p2.pop()
    return (p1, p2)


def get_remote_links(g, n1, p1):
    """
    returns the remote node and remote port pointed by port 'p1' in node 'n1' in g
    returns tuple (n2, p2)
    """
    n2 = [n for i, (p,n) in enumerate(g.node[n1]['link_to']) if p == p1]
    # if there is no edge between n1 and n2, no need to do anything
    # (n1,n2) may have been deleted and this is a race condition
    if not n2:
        return (None, None)
    # XXX super ugly...fix comprenhension to not return list
    n2 = n2.pop()
    p2 = [p for i, (p,n) in enumerate(g.node[n2]['link_to']) if n == n1]
    if not p2: 
        return (None, None)
    # XXX ugly...fix comprenhension to not return list
    p2 = p2.pop()
    return (n2, p2)


def delete_edge(g, n1, n2):
    """
    frees the ports linking n1 and n2 and removes the edge from topo
    """
    # search for the ports that links n1 and n2
    p1, p2 = get_linking_ports(g, n1, n2)
    if not (p1 and p2):
        log.error('No ports linking switch %s and %s. Edge not deleted' % (n1, n2))
        return
    # remove ports from nodes
    if (p1, n2) in g.node[n1]['link_to']:
        g.node[n1]['link_to'].remove((p1, n2))
        log.info('Switch %s Port %s DOWN' % (n1, p1))
    if (p2, n1) in g.node[n2]['link_to']:
        g.node[n2]['link_to'].remove((p2, n1))
        log.info('Switch %s Port %s DOWN' % (n2, p2))
    # remove edge from topo
    g.remove_edge(n1,n2)
    log.debug('Link between switch %s and switch %s removed' % (n1, n2))

