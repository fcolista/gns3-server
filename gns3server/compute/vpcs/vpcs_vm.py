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

"""
VPCS VM management (creates command line, processes, files etc.) in
order to run a VPCS VM.
"""

import os
import sys
import re
import asyncio

from ...utils.asyncio.embed_shell import create_telnet_shell
from .vpcs_error import VPCSError
from .vpcs_device import VpcsDevice
from ..adapters.ethernet_adapter import EthernetAdapter
from ..nios.nio_udp import NIOUDP
from ..nios.nio_tap import NIOTAP
from ..base_node import BaseNode


import logging
log = logging.getLogger(__name__)


class VPCSVM(BaseNode):
    module_name = 'vpcs'

    """
    VPCS VM implementation.

    :param name: VPCS VM name
    :param node_id: Node identifier
    :param project: Project instance
    :param manager: Manager instance
    :param console: TCP console port
    :param startup_script: content of the startup script file
    """

    def __init__(self, name, node_id, project, manager, console=None, startup_script=None):

        super().__init__(name, node_id, project, manager, console=console)
        self._started = False
        self._local_udp_tunnel = None
        self._device_shell = None

        # VPCS settings
        if startup_script is not None and not self.script_file:  # We disallow override at startup
            self.startup_script = startup_script
        self._ethernet_adapter = EthernetAdapter()  # one adapter with 1 Ethernet interface

    @asyncio.coroutine
    def close(self):
        """
        Closes this VPCS VM.
        """

        if not (yield from super().close()):
            return False

        nio = self._ethernet_adapter.get_nio(0)
        if isinstance(nio, NIOUDP):
            self.manager.port_manager.release_udp_port(nio.lport, self._project)

        if self._local_udp_tunnel:
            self.manager.port_manager.release_udp_port(self._local_udp_tunnel[0].lport, self._project)
            self.manager.port_manager.release_udp_port(self._local_udp_tunnel[1].lport, self._project)
            self._local_udp_tunnel = None

        yield from self._stop_ubridge()

        return True

    @asyncio.coroutine
    def _check_requirements(self):
        """
        Check if ubridge is available
        """

        # This raise an error if ubridge is not available
        self.ubridge_path

    def __json__(self):

        return {"name": self.name,
                "node_id": self.id,
                "node_directory": self.working_dir,
                "status": self.status,
                "console": self._console,
                "console_type": "telnet",
                "project_id": self.project.id,
                "command_line": self.command_line}

    @property
    def relative_startup_script(self):
        """
        Returns the startup config file relative to the project directory.

        :returns: path to config file. None if the file doesn't exist
        """

        path = os.path.join(self.working_dir, 'startup.vpc')
        if os.path.exists(path):
            return 'startup.vpc'
        else:
            return None

    @BaseNode.name.setter
    def name(self, new_name):
        """
        Sets the name of this VPCS VM.

        :param new_name: name
        """

        if self.script_file:
            content = self.startup_script
            content = content.replace(self._name, new_name)
            escaped_name = re.escape(new_name)
            content = re.sub(r"^set pcname .+$", "set pcname " + escaped_name, content, flags=re.MULTILINE)
            self.startup_script = content

        super(VPCSVM, VPCSVM).name.__set__(self, new_name)

    @property
    def startup_script(self):
        """
        Returns the content of the current startup script
        """

        script_file = self.script_file
        if script_file is None:
            return None

        try:
            with open(script_file, "rb") as f:
                return f.read().decode("utf-8", errors="replace")
        except OSError as e:
            raise VPCSError('Cannot read the startup script file "{}": {}'.format(script_file, e))

    @startup_script.setter
    def startup_script(self, startup_script):
        """
        Updates the startup script.

        :param startup_script: content of the startup script
        """

        try:
            startup_script_path = os.path.join(self.working_dir, 'startup.vpc')
            with open(startup_script_path, "w+", encoding='utf-8') as f:
                if startup_script is None:
                    f.write('')
                else:
                    startup_script = startup_script.replace("%h", self._name)
                    f.write(startup_script)
        except OSError as e:
            raise VPCSError('Cannot write the startup script file "{}": {}'.format(startup_script_path, e))

    @asyncio.coroutine
    def start(self):
        """
        Starts the VPCS process.
        """

        yield from self._check_requirements()
        if not self.is_running():
            nio = self._ethernet_adapter.get_nio(0)
            if not self._local_udp_tunnel:
                self._local_udp_tunnel = self._create_local_udp_tunnel()
            lnio = self._local_udp_tunnel[0]
            self._device = VpcsDevice(dst=(lnio.rhost, lnio.rport),
                                      working_directory=self.working_dir)

            # TODO: Replace that by proper mac management
            self._device.mac_address = "00:50:79:68:90:1" + str(self._manager.get_mac_id(self.id))
            self._device.ip_address = "192.168.1." + str(self._manager.get_mac_id(self.id) + 1)

            self._device_shell = create_telnet_shell(self._device)
            self._device_shell_server = yield from asyncio.start_server(self._device_shell.run, "0.0.0.0", self.console)

            self._device_transport, _ = yield from asyncio.get_event_loop().create_datagram_endpoint(lambda: self._device, local_addr=("0.0.0.0", lnio.lport))

            yield from self._start_ubridge()
            if nio:
                yield from self._add_ubridge_udp_connection("VPCS-{}".format(self._id), self._local_udp_tunnel[1], nio)

            log.info("VPCS instance {} started".format(self.name))
            self._started = True
            self.status = "started"

    @asyncio.coroutine
    def stop(self):
        """
        Stops the VPCS process.
        """

        yield from self._stop_ubridge()
        if self._device_shell:
            self._device_shell_server.close()
            self._device_transport.close()
            self._device_shell = None
        self._started = False
        yield from super().stop()

    @asyncio.coroutine
    def reload(self):
        """
        Reloads the VPCS process (stop & start).
        """

        yield from self.stop()
        yield from self.start()

    def is_running(self):
        """
        Checks if the VPCS process is running

        :returns: True or False
        """
        return self._started

    @asyncio.coroutine
    def port_add_nio_binding(self, port_number, nio):
        """
        Adds a port NIO binding.

        :param port_number: port number
        :param nio: NIO instance to add to the slot/port
        """

        if not self._ethernet_adapter.port_exists(port_number):
            raise VPCSError("Port {port_number} doesn't exist in adapter {adapter}".format(adapter=self._ethernet_adapter,
                                                                                           port_number=port_number))

        if self.ubridge:
            yield from self._add_ubridge_udp_connection("VPCS-{}".format(self._id), self._local_udp_tunnel[1], nio)
        elif self.is_running():
            raise VPCSError("Sorry, adding a link to a started VPCS instance is not supported without using uBridge.")

        self._ethernet_adapter.add_nio(port_number, nio)
        log.info('VPCS "{name}" [{id}]: {nio} added to port {port_number}'.format(name=self._name,
                                                                                  id=self.id,
                                                                                  nio=nio,
                                                                                  port_number=port_number))

        return nio

    @asyncio.coroutine
    def port_remove_nio_binding(self, port_number):
        """
        Removes a port NIO binding.

        :param port_number: port number

        :returns: NIO instance
        """

        if not self._ethernet_adapter.port_exists(port_number):
            raise VPCSError("Port {port_number} doesn't exist in adapter {adapter}".format(adapter=self._ethernet_adapter,
                                                                                           port_number=port_number))

        if self.ubridge:
            yield from self._ubridge_send("bridge delete {name}".format(name="VPCS-{}".format(self._id)))
        elif self.is_running():
            raise VPCSError("Sorry, adding a link to a started VPCS instance is not supported without using uBridge.")

        nio = self._ethernet_adapter.get_nio(port_number)
        if isinstance(nio, NIOUDP):
            self.manager.port_manager.release_udp_port(nio.lport, self._project)
        self._ethernet_adapter.remove_nio(port_number)

        log.info('VPCS "{name}" [{id}]: {nio} removed from port {port_number}'.format(name=self._name,
                                                                                      id=self.id,
                                                                                      nio=nio,
                                                                                      port_number=port_number))
        return nio

    @asyncio.coroutine
    def start_capture(self, port_number, output_file):
        """
        Starts a packet capture.

        :param port_number: port number
        :param output_file: PCAP destination file for the capture
        """

        if not self._ethernet_adapter.port_exists(port_number):
            raise VPCSError("Port {port_number} doesn't exist in adapter {adapter}".format(adapter=self._ethernet_adapter,
                                                                                           port_number=port_number))
        nio = self._ethernet_adapter.get_nio(0)

        if not nio:
            raise VPCSError("Port {} is not connected".format(port_number))

        if nio.capturing:
            raise VPCSError("Packet capture is already activated on port {port_number}".format(port_number=port_number))

        nio.startPacketCapture(output_file)

        if self.ubridge:
            yield from self._ubridge_send('bridge start_capture {name} "{output_file}"'.format(name="VPCS-{}".format(self._id),
                                                                                               output_file=output_file))

        log.info("VPCS '{name}' [{id}]: starting packet capture on port {port_number}".format(name=self.name,
                                                                                              id=self.id,
                                                                                              port_number=port_number))

    @asyncio.coroutine
    def stop_capture(self, port_number):
        """
        Stops a packet capture.

        :param port_number: port number
        """

        if not self._ethernet_adapter.port_exists(port_number):
            raise VPCSError("Port {port_number} doesn't exist in adapter {adapter}".format(adapter=self._ethernet_adapter,
                                                                                           port_number=port_number))

        nio = self._ethernet_adapter.get_nio(0)

        if not nio:
            raise VPCSError("Port {} is not connected".format(port_number))

        nio.stopPacketCapture()

        if self.ubridge:
            yield from self._ubridge_send('bridge stop_capture {name}'.format(name="VPCS-{}".format(self._id)))

        log.info("VPCS '{name}' [{id}]: stopping packet capture on port {port_number}".format(name=self.name,
                                                                                              id=self.id,
                                                                                              port_number=port_number))

    @property
    def script_file(self):
        """
        Returns the startup script file for this VPCS VM.

        :returns: path to startup script file
        """

        # use the default VPCS file if it exists
        path = os.path.join(self.working_dir, 'startup.vpc')
        if os.path.exists(path):
            return path
        else:
            return None
