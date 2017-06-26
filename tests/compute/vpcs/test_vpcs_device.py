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

import os
import pytest
import asyncio
from unittest.mock import MagicMock
from pypacker.layer12 import arp, ethernet
from pypacker.layer3 import ip, icmp

from tests.utils import asyncio_patch

from gns3server.compute.vpcs.vpcs_device import VpcsDevice


@pytest.fixture
def src_addr():
    return MagicMock()


@pytest.fixture(scope="function")
def computer(src_addr, loop, tmpdir):
    computer = VpcsDevice(dst=src_addr, loop=loop, working_directory=str(tmpdir))
    computer.transport = MagicMock()
    computer.mac_address = "12:34:56:78:90:12"
    computer.ip_address = "192.168.1.2"

    def assert_sendto(response):
        """
        Wrapper to check if sendto is called with the correct
        parameters and display proper debug informations.
        """
        assert computer.transport.sendto.called
        args = []
        for args, kwargs in computer.transport.sendto.call_args_list:
            if args[0] == response.bin() and args[1] == src_addr:
                return
        # No match display debug informations
        assert args[1] == src_addr
        packet = ethernet.Ethernet(args[0])
        for layer in response:
            assert str(packet[type(layer)]) == str(layer)

    computer.assert_sendto = assert_sendto

    return computer


def test_computer_arp_received(computer, src_addr):
    arpreq = ethernet.Ethernet(src_s="12:34:56:78:90:13",
                               type=ethernet.ETH_TYPE_ARP) + \
        arp.ARP(sha_s="12:34:56:78:90:13",
                spa_s="192.168.1.1",
                tha_s="FF:FF:FF:FF:FF:FF",
                tpa_s="0.0.0.0")
    computer.datagram_received(arpreq.bin(), src_addr)

    response = ethernet.Ethernet(
        src_s=computer.mac_address,
        type=ethernet.ETH_TYPE_ARP) + \
        arp.ARP(
            op=arp.ARP_OP_REPLY,
            sha_s=computer.mac_address,
            spa_s=computer.ip_address,
            tha=arpreq[arp.ARP].sha,
            tpa=arpreq[arp.ARP].spa)

    computer.assert_sendto(response)
    assert computer._arp_cache["192.168.1.1"] == "12:34:56:78:90:13"


def test_computer_arp_received_not_for_me(computer, src_addr):
    arpreq = ethernet.Ethernet(src_s="12:34:56:78:90:13",
                               type=ethernet.ETH_TYPE_ARP) + \
        arp.ARP(sha_s="12:34:56:78:90:13",
                spa_s="192.168.0.1",
                tha_s="12:34:56:78:90:00",
                tpa_s=computer.ip_address)
    computer.datagram_received(arpreq.bin(), src_addr)
    assert not computer.transport.sendto.called


def test_icmp_echo_reply(computer, src_addr):
    icmpreq = ethernet.Ethernet(src_s="12:34:56:78:90:13",
                                dst_s=computer.mac_address,
                                type=ethernet.ETH_TYPE_IP) + \
        ip.IP(p=ip.IP_PROTO_ICMP,
              src_s="192.168.1.1",
              dst_s=computer.ip_address) + \
        icmp.ICMP(type=icmp.ICMP_ECHOREPLY) + \
        icmp.ICMP.Echo(id=54, seq=12)
    computer.datagram_received(icmpreq.bin(), src_addr)
    icmpreq.reverse_all_address()
    computer.assert_sendto(icmpreq)


def test_icmp_echo_reply_to_our_ping(computer, src_addr):
    """
    If the packet is sent by us do not reply
    """
    computer._icmp_sent_ids.add(54)
    icmpreq = ethernet.Ethernet(src_s="12:34:56:78:90:13",
                                dst_s=computer.mac_address,
                                type=ethernet.ETH_TYPE_IP) + \
        ip.IP(p=ip.IP_PROTO_ICMP,
              src_s="192.168.1.1",
              dst_s=computer.ip_address) + \
        icmp.ICMP(type=icmp.ICMP_ECHOREPLY) + \
        icmp.ICMP.Echo(id=54, seq=12)
    computer.datagram_received(icmpreq.bin(), src_addr)
    assert computer.transport.sendto.called is False
    assert len(computer._icmp_sent_ids) == 0


def test_ping(computer, async_run):
    @asyncio.coroutine
    def get_icmp_packet():
        packet, addr = computer.transport.sendto.call_args[0]
        packet = ethernet.Ethernet(packet)
        packet.reverse_all_address()
        assert packet[icmp.ICMP.Echo].id in computer._icmp_sent_ids
        return packet

    computer._icmp_queue.get = get_icmp_packet
    computer._arp_cache["192.168.1.1"] = "12:34:56:78:90:13"
    res = async_run(computer.ping("192.168.1.1"))
    assert len(res.strip().split("\n")) == 5
    assert "ttl=64" in res
    assert "64 bytes" in res
    assert " from 192.168.1.1 " in res


@pytest.mark.timeout(40)
def test_ping_timeout(computer, async_run):
    computer._arp_cache["192.168.1.1"] = "12:34:56:78:90:13"
    res = async_run(computer.ping("192.168.1.1", timeout=0.5))
    assert len(res.strip().split("\n")) == 5
    assert "192.168.1.1 icmp_seq=1 timeout" in res


@pytest.mark.timeout(0)
def test_ping_unknow_host(computer, async_run):
    res = async_run(computer.ping("192.168.1.5", timeout=0.5))
    assert res == "host (192.168.1.5) not reachable\n"


def test_set_invalid(computer, async_run):
    res = async_run(computer.set("dsfsdfsd"))
    assert res == "Invalid command."


def test_set_pcname(computer, async_run):
    res = async_run(computer.set("pcname"))
    assert res == "Incomplete command."

    res = async_run(computer.set("pcname", "TEST"))
    assert res == ""
    assert computer._settings["pcname"] == "TEST"
    assert computer.prompt == "TEST> "


def test_echo(computer, async_run):
    res = async_run(computer.echo())
    assert res == ""

    res = async_run(computer.echo("hello", "world"))
    assert res == "hello world"


def test_save(tmpdir, async_run, computer):
    async_run(computer.set("pcname", "TEST"))
    assert async_run(computer.save()) == 'Saving startup configuration to startup.vpc'
    with open(str(tmpdir / "startup.vpc")) as f:
        content = f.read()
    assert content == 'set pcname TEST\n'


def test_read_startup(tmpdir, computer, async_run):
    with open(str(tmpdir / 'startup.vpc'), 'w+') as f:
        f.write('set pcname TEST\n')
    with asyncio_patch('gns3server.utils.asyncio.embed_shell.EmbedShell.run'):
        async_run(computer.run())
    assert computer._settings["pcname"] == "TEST"
    assert computer.prompt == "TEST> "
