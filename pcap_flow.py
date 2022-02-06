from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from ipaddress import ip_address, IPv6Address
from socket import IPPROTO_TCP
import sys
import matplotlib.pyplot as plt

class Flow(object):
    def __init__(self, data):
        global ip, tcp
        dst_address = ''
        src_address = ''
        global lens
        self.pkts = 0
        self.flows = 0
        self.ft = {}
        # pkts = [p for i, (p, m) in enumerate(RawPcapReader(data)) if i < 10]
        # pp = pkts[0]
        # ether = Ether(pp)
        # ip = ether[IP]
        # print(ip.src)
        for pkt, metadata in RawPcapReader(data):
            self.pkts += 1
            ether = Ether(pkt)
            if ether.type == 0x86dd:
                ip = ether[IPv6]
                #
                # write your code here
                if ip.nh != IPPROTO_TCP:
                    continue
                src_ip = ip.src
                src_address = ip_address(src_ip)
                dst_ip = ip.dst
                dst_address = ip_address(dst_ip)

                lens = ip.plen
                #
            elif ether.type == 0x0800:
                ip = ether[IP]
                #
                # write your code here

                if ip.proto != IPPROTO_TCP:
                    continue
                src_ip = ip.src
                print(type(src_ip))
                src_address = ip_address(src_ip)
                dst_ip = ip.dst
                dst_address = ip_address(dst_ip)

                lens = ip.len - ip.ihl * 4
                #
            #
            # write your code here
            if not ip.haslayer(TCP):
                continue
            tcp = ip[TCP]
            lens -= tcp.dataofs * 4

            if lens == 0:
                continue

            src_port = tcp.sport
            dst_port = tcp.dport
            index1 = (int(src_address), int(dst_address), src_port, dst_port)
            index2 = (int(dst_address), int(src_address), dst_port, src_port)

            # if index1 in self.ft.keys() or index2 in self.ft.keys():
            #     continue
            # else:
            #     self.ft[index1] = lens
            if index1 in self.ft:
                self.ft[index1] += lens
            elif index2 in self.ft:
                self.ft[index2] += lens
            else:
                self.ft[index1] = lens

    def Plot(self):
        topn = 100
        data = [i/1000 for i in list(self.ft.values())]
        data.sort()
        data = data[-topn:]
        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        ax.hist(data, bins=50, log=True)
        ax.set_ylabel('# of flows')
        ax.set_xlabel('Data sent [KB]')
        ax.set_title('Top {} TCP flow size distribution.'.format(topn))
        plt.savefig(sys.argv[1] + '.flow.pdf', bbox_inches='tight')
        plt.close()
    def _Dump(self):
        with open(sys.argv[1] + '.flow.data', 'w') as f:
            f.write('{}'.format(self.ft))

if __name__ == '__main__':
    d = Flow(sys.argv[1])
    d.Plot()
    d._Dump()
