#!/usr/bin/env python
#
# Copyright (C) 2017 GNS3 Technologies Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import asyncio
from pypacker.layer12 import arp, ethernet
from pypacker.layer3 import icmp, ip


from gns3server.utils.asyncio.embed_shell import EmbedShell, create_stdin_shell


class Computer(EmbedShell):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip_address = None
        self.mac_address = None

    @asyncio.coroutine
    def ping(self, host):
        """
        Ping remote machine

        Usage: ping hostname or ip
        """
        return 'Ping / Pong'

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        print('Data received:', addr)
        packet = ethernet.Ethernet(data)
        if packet[arp.ARP]:
            arp_layer = packet[arp.ARP]
            print(arp_layer.tha_s)
            if arp_layer.tha_s != self.mac_address and arp_layer.tha_s != "FF:FF:FF:FF:FF:FF":
                return
            if arp_layer.op == arp.ARP_OP_REQUEST:
                arpreq = ethernet.Ethernet(src_s=self.mac_address,
                                           type=ethernet.ETH_TYPE_ARP) + \
                    arp.ARP(op=arp.ARP_OP_REPLY,
                            sha_s=self.mac_address,
                            spa_s=self.ip_address,
                            tha=arp_layer.sha,
                            tpa=arp_layer.spa)
                print('REPLY', arp_layer.tha_s)
                self.transport.sendto(arpreq.bin(), addr)
        if packet[icmp.ICMP.Echo]:
            icmp_layer = packet[icmp.ICMP.Echo]
            icmpreq = ethernet.Ethernet(src_s=self.mac_address,
                                        dst=packet.src,
                                        type=ethernet.ETH_TYPE_IP) + \
                ip.IP(p=ip.IP_PROTO_ICMP,
                      src_s=self.ip_address,
                      dst_s="192.168.1.1") + \
                icmp.ICMP(type=icmp.ICMP_ECHOREPLY) + \
                icmp.ICMP.Echo(id=icmp_layer.id, seq=icmp_layer.seq)
            #self.transport.sendto(icmpreq.bin(), addr)


class VpcsDevice:
    """
    This replace the vpcs binary with a pure python
    implementation
    """
    @asyncio.coroutine
    def run(self, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        shell = Computer()
        shell.mac_address = "12:34:56:78:90:13"
        shell.ip_address = "192.168.1.2"
        shell.prompt = "VPCS> "
        self._shell_task = create_stdin_shell(shell)
        self._computer_task = asyncio.Task(loop.create_datagram_endpoint(lambda: shell, local_addr=('127.0.0.1', 5555)))
        return asyncio.gather(self._shell_task, self._computer_task)


if __name__ == '__main__':
    # To test start with python -m gns3server.compute.vpcs.vpcs_device
    # and vpcs with vpcs -c 5555
    loop = asyncio.get_event_loop()
    loop.run_until_complete(VpcsDevice().run())
    loop.close()
