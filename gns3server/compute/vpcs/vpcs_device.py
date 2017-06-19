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

import time
import random
import asyncio
from pypacker.layer12 import arp, ethernet
from pypacker.layer3 import icmp, ip


from gns3server.utils.asyncio.embed_shell import EmbedShell, create_stdin_shell


class Computer(EmbedShell):

    def __init__(self, *args, dst=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip_address = None
        self.mac_address = None
        self.dst_addr = dst
        self._arp_cache = {}

        # ICMP reply are stored to be consume by the ping command
        self._icmp_queue = asyncio.Queue()
        # List of ICMP identifiers use by us
        self._icmp_sent_ids = set()

        # Order is important if a layer return
        # false we stop the processing
        self._layer_handlers = [
            (arp.ARP, self._handle_arp),
            (icmp.ICMP.Echo, self._handle_icmp_echo)
        ]

    @asyncio.coroutine
    def ping(self, host):
        """
        Ping remote machine

        Usage: ping hostname or ip
        """
        msg = ""
        seq = 1
        dst = yield from self._resolve(host)
        self._icmp_sent_ids = set()
        while seq <= 5:
            id = random.getrandbits(16)
            self._icmp_sent_ids.add(id)
            icmpreq = ethernet.Ethernet(src_s=self.mac_address,
                                        dst_s=dst,
                                        type=ethernet.ETH_TYPE_IP) + \
                ip.IP(p=ip.IP_PROTO_ICMP,
                      src_s=self.ip_address,
                      dst_s=host) + \
                icmp.ICMP(type=icmp.ICMP_ECHOREPLY) + \
                icmp.ICMP.Echo(id=id, seq=seq, ts=int(time.time()), body_bytes=b"x" * 64)
            self.transport.sendto(icmpreq.bin(), self.dst_addr)
            reply = yield from self._icmp_queue.get()
            ip_packet = reply[ip.IP]
            icmp_packet = reply[icmp.ICMP.Echo]
            msg += "{} bytes from {} icmp_seq={} ttl={} time={} ms\n".format(
                len(icmp_packet.body_bytes),
                ip_packet.src_s,
                icmp_packet.seq,
                ip_packet.ttl,
                round(time.time() - icmp_packet.ts, 3)
            )
            seq += 1
        return msg

    @asyncio.coroutine
    def _resolve(self, host):
        #TODO: Support DNS
        return self._arp_cache[host]

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        self.transport = None

    def datagram_received(self, data, src_addr):
        packet = ethernet.Ethernet(data)
        for procotol, layer_handler in self._layer_handlers:
            if packet[procotol]:
                reply = layer_handler(packet[procotol], packet)
                if reply is False:
                    return
                elif reply is not None:
                    self.transport.sendto(reply.bin(), src_addr)

    def _handle_arp(self, arp_layer, packet):
        self._arp_cache[arp_layer.spa_s] = arp_layer.sha_s
        if arp_layer.tha_s != self.mac_address and arp_layer.tha_s != "FF:FF:FF:FF:FF:FF":
            return False
        if arp_layer.op == arp.ARP_OP_REQUEST:
            arpreq = ethernet.Ethernet(src_s=self.mac_address,
                                       type=ethernet.ETH_TYPE_ARP) + \
                arp.ARP(op=arp.ARP_OP_REPLY,
                        sha_s=self.mac_address,
                        spa_s=self.ip_address,
                        tha=arp_layer.sha,
                        tpa=arp_layer.spa)
            return arpreq

    def _handle_icmp_echo(self, icmp_layer, packet):
        if icmp_layer.id in self._icmp_sent_ids:
            self._icmp_sent_ids.remove(icmp_layer.id)
            asyncio.async(self._icmp_queue.put(packet))
            return False

        icmpreq = ethernet.Ethernet(src_s=self.mac_address,
                                    dst=packet.src,
                                    type=ethernet.ETH_TYPE_IP) + \
            ip.IP(p=ip.IP_PROTO_ICMP,
                  src_s=self.ip_address,
                  dst_s=packet[ip.IP].src_s) + \
            icmp.ICMP(type=0) + \
            icmp.ICMP.Echo(id=icmp_layer.id, seq=icmp_layer.seq)
        return icmpreq


class VpcsDevice:
    """
    This replace the vpcs binary with a pure python
    implementation
    """
    @asyncio.coroutine
    def run(self, loop=None):
        if loop is None:
            loop = asyncio.get_event_loop()
        shell = Computer(dst=("127.0.0.1", 5555))
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
