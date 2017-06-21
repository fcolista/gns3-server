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
from pypacker import ppcap


from gns3server.utils.asyncio.embed_shell import EmbedShell, create_stdin_shell


class Computer(EmbedShell):

    def __init__(self, *args, dst=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip_address = None
        self.mac_address = None
        self.dst_addr = dst
        self._arp_cache = {}

        # For debug set it's to None if you want to disable it
        self._pcap_writer = ppcap.Writer(filename="/tmp/debug.pcap")

        # ICMP reply are stored to be consume by the ping command
        self._icmp_queue = asyncio.Queue(loop=self._loop)
        # List of ICMP identifiers use by us
        self._icmp_sent_ids = set()

        # Order is important if a layer return
        # false we stop the processing
        self._layer_handlers = [
            (arp.ARP, self._handle_arp),
            (icmp.ICMP.Echo, self._handle_icmp_echo)
        ]

    @asyncio.coroutine
    def quit(self):
        """
        FOR DEBUG
        """
        #TODO: REMOVE
        import sys
        sys.exit(0)
        if self._pcap_writer:
            self._pcap_writer.close()

    @asyncio.coroutine
    def ping(self, host="192.168.1.1"):
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
            self.sendto(icmpreq)
            done, pending = yield from asyncio.wait([self._icmp_queue.get()], loop=self._loop, timeout=5)
            if len(done) == 0:
                print('FAIL' + host + dst)
            else:
                reply = done.pop()
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
        while True:
            if host in self._arp_cache:
                return self._arp_cache[host]
            elif host == self.ip_address:
                return self.mac_address
            else:
                arpreq = ethernet.Ethernet(
                    src_s=self.mac_address,
                    type=ethernet.ETH_TYPE_ARP) + \
                    arp.ARP(sha_s=self.mac_address,
                            spa_s=self.ip_address,
                            tha_s="FF:FF:FF:FF:FF:FF",
                            tpa_s=host,
                            op=arp.ARP_OP_REQUEST)
                self.sendto(arpreq)
                yield from asyncio.sleep(0.5)

    def sendto(self, packet):
        if self._pcap_writer:
            self._pcap_writer.write(packet.bin())
        self.transport.sendto(packet.bin(), self.dst_addr)

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        self.transport = None

    def datagram_received(self, data, src_addr):
        packet = ethernet.Ethernet(data)
        print(packet)
        if self._pcap_writer:
            self._pcap_writer.write(packet.bin())
        for procotol, layer_handler in self._layer_handlers:
            if packet[procotol]:
                reply = layer_handler(packet[procotol], packet)
                if reply is False:
                    return
                elif reply is not None:
                    self.sendto(reply)

    def _handle_arp(self, arp_layer, packet):
        if arp_layer.sha_s == self.mac_address:  # It's ourself
            return False
        self._arp_cache[arp_layer.spa_s] = arp_layer.sha_s
        if arp_layer.tha_s != self.mac_address and arp_layer.tha_s != "FF:FF:FF:FF:FF:FF":
            return False
        if arp_layer.spa_s == arp_layer.tpa_s:  # Gratuitous no need to reply
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
        shell = Computer(dst=("127.0.0.1", 5556))
        shell.mac_address = "00:50:79:68:90:13"
        shell.ip_address = "192.168.1.2"
        shell.prompt = "VPCS> "
        self._shell_task = create_stdin_shell(shell)
        self._computer_task = asyncio.Task(loop.create_datagram_endpoint(lambda: shell, local_addr=('127.0.0.1', 5555)))
        return asyncio.gather(self._shell_task, self._computer_task)


if __name__ == '__main__':
    # To test start with python -m gns3server.compute.vpcs.vpcs_device
    # and vpcs with vpcs -c 5555 -s 5556
    loop = asyncio.get_event_loop()
    loop.run_until_complete(VpcsDevice().run())
    loop.close()
