# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 GNS3 Technologies Inc.
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
import aiohttp
import asyncio
import os
import sys

from tests.utils import asyncio_patch, AsyncioMagicMock
from gns3server.utils import parse_version
from unittest.mock import patch, MagicMock, ANY

from gns3server.compute.vpcs.vpcs_vm import VPCSVM
from gns3server.compute.vpcs.vpcs_error import VPCSError
from gns3server.compute.vpcs import VPCS
from gns3server.compute.notification_manager import NotificationManager


@pytest.fixture
def manager(port_manager):
    m = VPCS.instance()
    m.port_manager = port_manager
    return m


@pytest.fixture(scope="function")
def vm(project, manager, ubridge_path):
    vm = VPCSVM("test", "00010203-0405-0607-0809-0a0b0c0d0e0f", project, manager)
    vm._vpcs_version = parse_version("0.9")
    vm._start_ubridge = AsyncioMagicMock()
    return vm


def test_vm(project, manager):
    vm = VPCSVM("test", "00010203-0405-0607-0809-0a0b0c0d0e0f", project, manager)
    assert vm.name == "test"
    assert vm.id == "00010203-0405-0607-0809-0a0b0c0d0e0f"


def test_start(loop, vm, async_run):
    vm._check_requirements = AsyncioMagicMock(return_value=True)
    vm._add_ubridge_udp_connection = AsyncioMagicMock()
    vm._manager.get_mac_id = MagicMock(return_value=3)

    with NotificationManager.instance().queue() as queue:
        async_run(queue.get(0))  # Ping

        nio = VPCS.instance().create_nio({"type": "nio_udp", "lport": 4242, "rport": 4243, "rhost": "127.0.0.1"})
        async_run(vm.port_add_nio_binding(0, nio))
        loop.run_until_complete(asyncio.async(vm.start()))
        (action, event, kwargs) = async_run(queue.get(0))
        assert action == "node.updated"
        assert event == vm

        assert vm._device.mac_address == "00:50:79:68:90:13"
        assert vm._device.ip_address == "192.168.1.4"
        assert vm._device_shell
        assert vm._device_transport
        assert vm._device_shell_server


def test_stop(loop, vm, async_run):
    vm._check_requirements = AsyncioMagicMock(return_value=True)
    vm._add_ubridge_udp_connection = AsyncioMagicMock()

    vm._device_shell = MagicMock()
    mock_transport = MagicMock()
    vm._device_transport = mock_transport
    mock_shell_server = MagicMock()
    vm._device_shell_server = mock_shell_server
    vm._started = True

    with NotificationManager.instance().queue() as queue:
        loop.run_until_complete(asyncio.async(vm.stop()))
        assert vm.is_running() is False

        async_run(queue.get(0))  # Ping

        (action, event, kwargs) = async_run(queue.get(0))
        assert action == "node.updated"
        assert event == vm
        assert mock_transport.close.called
        assert mock_shell_server.close.called


def test_reload(loop, vm, async_run):
    vm._check_requirements = AsyncioMagicMock(return_value=True)
    vm._add_ubridge_udp_connection = AsyncioMagicMock()

    nio = VPCS.instance().create_nio({"type": "nio_udp", "lport": 4242, "rport": 4243, "rhost": "127.0.0.1"})
    async_run(vm.port_add_nio_binding(0, nio))
    async_run(vm.start())
    assert vm.is_running()

    async_run(vm.reload())
    assert vm.is_running() is True


def test_add_nio_binding_udp(vm, async_run):
    nio = VPCS.instance().create_nio({"type": "nio_udp", "lport": 4242, "rport": 4243, "rhost": "127.0.0.1"})
    async_run(vm.port_add_nio_binding(0, nio))
    assert nio.lport == 4242


@pytest.mark.skipif(sys.platform.startswith("win"), reason="Not supported on Windows")
def test_add_nio_binding_tap(vm, ethernet_device):
    with patch("gns3server.compute.base_manager.BaseManager.has_privileged_access", return_value=True):
        nio = VPCS.instance().create_nio({"type": "nio_tap", "tap_device": ethernet_device})
        vm.port_add_nio_binding(0, nio)
        assert nio.tap_device == ethernet_device


def test_port_remove_nio_binding(vm):
    nio = VPCS.instance().create_nio({"type": "nio_udp", "lport": 4242, "rport": 4243, "rhost": "127.0.0.1"})
    vm.port_add_nio_binding(0, nio)
    vm.port_remove_nio_binding(0)
    assert vm._ethernet_adapter.ports[0] is None


def test_update_startup_script(vm):
    content = "echo GNS3 VPCS\nip 192.168.1.2\n"
    vm.startup_script = content
    filepath = os.path.join(vm.working_dir, 'startup.vpc')
    assert os.path.exists(filepath)
    with open(filepath) as f:
        assert f.read() == content


def test_update_startup_script_h(vm):
    content = "set pcname %h\n"
    vm.name = "pc1"
    vm.startup_script = content
    assert os.path.exists(vm.script_file)
    with open(vm.script_file) as f:
        assert f.read() == "set pcname pc1\n"


def test_update_startup_script_with_escaping_characters_in_name(vm):
    vm.startup_script = "set pcname initial-name\n"
    vm.name = "test\\"
    assert vm.startup_script == "set pcname test\\\n"


def test_get_startup_script(vm):
    content = "echo GNS3 VPCS\nip 192.168.1.2"
    vm.startup_script = content
    assert vm.startup_script == os.linesep.join(["echo GNS3 VPCS", "ip 192.168.1.2"])


def test_get_startup_script_using_default_script(vm):
    content = "echo GNS3 VPCS\nip 192.168.1.2\n"

    # Reset script file location
    vm._script_file = None

    filepath = os.path.join(vm.working_dir, 'startup.vpc')
    with open(filepath, 'wb+') as f:
        assert f.write(content.encode("utf-8"))

    assert vm.startup_script == content
    assert vm.script_file == filepath


def test_change_name(vm, tmpdir):
    path = os.path.join(vm.working_dir, 'startup.vpc')
    vm.name = "world"
    with open(path, 'w+') as f:
        f.write("set pcname world")
    vm.name = "hello"
    assert vm.name == "hello"
    with open(path) as f:
        assert f.read() == "set pcname hello"
    # Support when the name is not sync with config
    with open(path, 'w+') as f:
        f.write("set pcname alpha")
    vm.name = "beta"
    assert vm.name == "beta"
    with open(path) as f:
        assert f.read() == "set pcname beta"


def test_close(vm, port_manager, loop):
    with asyncio_patch("gns3server.compute.vpcs.vpcs_vm.VPCSVM._check_requirements", return_value=True):
        with asyncio_patch("asyncio.create_subprocess_exec", return_value=MagicMock()):
            vm.start()
            loop.run_until_complete(asyncio.async(vm.close()))
            assert vm.is_running() is False
