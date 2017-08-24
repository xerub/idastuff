#  SCC IDA script
#
#  Copyright (c) 2015 xerub
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import idautils
import idc
import idaapi


def strongly_connected_components(graph):
    """
    Tarjan's Algorithm (named for its discoverer, Robert Tarjan) is a graph theory algorithm
    for finding the strongly connected components of a graph.

    Based on: http://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm
    """

    index_counter = [0]
    stack = []
    lowlinks = {}
    index = {}
    result = []

    def strongconnect(node):
        # set the depth index for this node to the smallest unused index
        index[node] = index_counter[0]
        lowlinks[node] = index_counter[0]
        index_counter[0] += 1
        stack.append(node)

        # Consider successors of `node`
        try:
            successors = graph[node]
        except:
            successors = []
        for successor in successors:
            if successor not in lowlinks:
                # Successor has not yet been visited; recurse on it
                strongconnect(successor)
                lowlinks[node] = min(lowlinks[node],lowlinks[successor])
            elif successor in stack:
                # the successor is in the stack and hence in the current strongly connected component (SCC)
                lowlinks[node] = min(lowlinks[node],index[successor])

        # If `node` is a root node, pop the stack and generate an SCC
        if lowlinks[node] == index[node]:
            connected_component = []

            while True:
                successor = stack.pop()
                connected_component.append(successor)
                if successor == node: break
            component = tuple(connected_component)
            # storing the result
            #result.append(component)
            if len(component) > 1 or node in successors: result.append(component)

    for node in graph:
        if node not in lowlinks:
            strongconnect(node)

    return result


def get_succ(func_start):
    succ = set()
    for h in idautils.FuncItems(func_start):
        for r in idautils.XrefsFrom(h, 0):
            if r.type == fl_CF or r.type == fl_CN:
                #print hex(h), "-->", hex(r.to)
                succ.add(r.to)
    return succ


graph = {}

print "+graph"
for f in idautils.Functions():
    sux = get_succ(f)
    if sux:
        graph[f] = sux

print "+tarjan"
result = strongly_connected_components(graph)

print "+done"
for r in result:
    for f in r:
        print(Name(f)),
    print "-"
