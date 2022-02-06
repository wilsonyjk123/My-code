from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from ipaddress import ip_address, ip_network
import sys
import matplotlib.pyplot as plt

class Node(object):
    def __init__(self, ip, plen):
        self.bytes = plen
        self.left = None
        self.right = None
        self.ip = ip
    def add(self, ip, plen):
        #
        # write your code here
        node = Node(ip,plen)
        if int(node.ip) < int(self.ip):
            if self.left == None:
                self.left = node
            else:
                self.left.add(ip,plen)

        if int(node.ip) == int(self.ip):
            self.bytes += plen

        if int(node.ip) > int(self.ip):
            if self.right == None:
                self.right = node
            else:
                self.right.add(ip,plen)
        #
    def data(self, data):
        if self.left:
            self.left.data(data)
        if self.bytes > 0:
            data[ip_network(self.ip)] = self.bytes
        if self.right:
            self.right.data(data)
    @staticmethod
    def supernet(ip1, ip2):
        na1 = ip_network(ip1).network_address
        na2 = ip_network(ip2).network_address

        split_na1 = str(na1).split('.')
        split_na2 = str(na2).split('.')
        new_split_na1 = []
        new_split_na2 = []

        for i in split_na1:
            new_split_na1.append('{:08b}'.format(int(i)))
        for i in split_na2:
            new_split_na2.append('{:08b}'.format(int(i)))

        netmask = 0
        string = ''
        str_na1 = string.join(new_split_na1)
        str_na2 = string.join(new_split_na2)
        for i in range(32):
            if str_na1[i] == str_na2[i]:
                netmask += 1
            else:
                break
        result = str_na1[0:netmask]
        result = result.ljust(32, '0')
        result = [result[0:8],result[8:16],result[16:24],result[24:32]]
        final = []

        for item in result:
            final.append(str(int(item, 2)))

        string_dot = '.'
        final = string_dot.join(final)
        na1 = final
        return ip_network('{}/{}'.format(na1, netmask), strict=False)

    def aggr(self, byte_thresh):
        #
        # write your code here
        boolean = False
        queue = [self]
        tree = []

        while queue:
            curNode = queue.pop(0)
            tree.append(curNode)
            if curNode.left:
                queue.append(curNode.left)
            if curNode.right:
                queue.append(curNode.right)
        tree.reverse()

        for node in tree:
            if not (node.left or node.right):
                continue
            if node.left:
                if node.left.bytes < byte_thresh:
                    node.bytes += node.left.bytes
                    node.ip = self.supernet(node.ip,node.left.ip)
                    if node.left.left or node.left.right:
                        node.left.bytes = 0
                    else:
                        node.left = None
            if node.right:
                if node.right.bytes < byte_thresh:
                    node.bytes += node.right.bytes
                    node.ip = self.supernet(node.ip, node.right.ip)
                    if node.right.left or node.right.right:
                        node.right.bytes = 0
                    else:
                        node.right = None

        res = list(filter(None, tree))
        #
            
class Data(object):
    def __init__(self, data):
        self.tot_bytes = 0
        self.data = {}
        self.aggr_ratio = 0.05
        root = None
        cnt = 0
        for pkt, metadata in RawPcapReader(data):
            ether = Ether(pkt)
            if not 'type' in ether.fields:
                continue
            if ether.type != 0x0800:
                continue
            ip = ether[IP]
            self.tot_bytes += ip.len
            if root is None:
                root = Node(ip_address(ip.src), ip.len)
            else:
                root.add(ip_address(ip.src), ip.len)
            cnt += 1
            # root = Node(ip_address('203.62.184.243'), 210)
            # root.add(ip_address('94.153.243.18'), 40)
            # root.add(ip_address('209.243.136.123'), 32)
            # root.add(ip_address('150.10.10.225'), 2277)
            # root.add(ip_address('146.121.1.156'), 40)
            # root.add(ip_address('203.62.165.212'), 64)
            # root.add(ip_address('202.132.97.10'), 40)
            # root.add(ip_address('202.132.100.13'), 40)
            # root.aggr(100)
        root.aggr(self.tot_bytes * self.aggr_ratio)
        root.data(self.data)
    def Plot(self):
        data = {k: v/1000 for k, v in self.data.items()}
        plt.rcParams['font.size'] = 8
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        ax.grid(which='major', axis='y')
        ax.tick_params(axis='both', which='major')
        ax.set_xticks(range(len(data)))
        ax.set_xticklabels([str(l) for l in data.keys()], rotation=45,
            rotation_mode='default', horizontalalignment='right')
        ax.set_ylabel('Total bytes [KB]')
        ax.bar(ax.get_xticks(), data.values(), zorder=2)
        ax.set_title('IPv4 sources sending {} % ({}KB) or more traffic.'.format(
            self.aggr_ratio * 100, self.tot_bytes * self.aggr_ratio / 1000))
        plt.savefig(sys.argv[1] + '.aggr.pdf', bbox_inches='tight')
        plt.close()
    def _Dump(self):
        with open(sys.argv[1] + '.aggr.data', 'w') as f:
            f.write('{}'.format({str(k): v for k, v in self.data.items()}))

if __name__ == '__main__':
    d = Data(sys.argv[1])
    d.Plot()
    d._Dump()
