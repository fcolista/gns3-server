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

import pytest
from unittest.mock import MagicMock
from pypacker.layer12 import arp, ethernet

from gns3server.compute.vpcs.vpcs_device import Computer


@pytest.fixture
def computer():
    computer = Computer()
    computer.transport = MagicMock()

    def assert_sendto(response, addr):
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
        assert args[1] == addr
        packet = ethernet.Ethernet(args[0])
        for layer in response:
            assert str(packet[type(layer)]) == str(layer)

    computer.assert_sendto = assert_sendto

    return computer


@pytest.fixture
def src_addr():
    return MagicMock()


def test_computer_arp_received(computer, src_addr):
    arpreq = ethernet.Ethernet(src_s="12:34:56:78:90:12",
                               type=ethernet.ETH_TYPE_ARP) + \
        arp.ARP(sha_s="12:34:56:78:90:12",
                spa_s="192.168.0.2",
                tha_s="12:34:56:78:90:13",
                tpa_s="192.168.0.1")
    computer.datagram_received(arpreq.bin(), src_addr)

    response = ethernet.Ethernet(
        src_s="12:34:56:78:90:12",
        type=ethernet.ETH_TYPE_ARP) + \
        arp.ARP(sha_s="12:34:56:78:90:12",
                spa_s="192.168.1.2",
                tha=arpreq[arp.ARP].sha,
                tpa=arpreq[arp.ARP].spa)

    computer.assert_sendto(response, src_addr)
