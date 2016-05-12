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

import asyncio
from aiohttp.web import HTTPForbidden

from ....web.route import Route
from ....config import Config
from ....compute.project_manager import ProjectManager
from ....schemas.compute import COMPUTE_CREATE_SCHEMA, COMPUTE_OBJECT_SCHEMA
from ....controller import Controller
from ....controller.compute import Compute


import logging
log = logging.getLogger(__name__)


class ComputeHandler:
    """API entry points for compute management."""

    @classmethod
    @Route.post(
        r"/computes",
        description="Register a compute",
        status_codes={
            201: "Compute added"
        },
        input=COMPUTE_CREATE_SCHEMA,
        output=COMPUTE_OBJECT_SCHEMA)
    def create(request, response):

        compute = yield from Controller.instance().add_compute(**request.json)
        response.set_status(201)
        response.json(compute)

    @classmethod
    @Route.get(
        r"/computes",
        description="List compute nodes",
        status_codes={
            200: "Compute list"
        })
    def list(request, response):

        controller = Controller.instance()
        response.json([c for c in controller.computes.values()])

    @classmethod
    @Route.get(
        r"/computes/{compute_id}",
        description="Get a compute node informations",
        status_codes={
            200: "Compute list"
        },
        output=COMPUTE_OBJECT_SCHEMA)
    def get(request, response):

        controller = Controller.instance()
        compute = controller.get_compute(request.match_info["compute_id"])
        response.json(compute)

    @classmethod
    @Route.post(
        r"/computes/shutdown",
        description="Shutdown the local compute",
        status_codes={
            201: "Compute is shutting down",
            403: "Compute shutdown refused"
        })
    def shutdown(request, response):

        config = Config.instance()
        if config.get_section_config("Server").getboolean("local", False) is False:
            raise HTTPForbidden(text="You can only stop a local server")

        # close all the projects first
        pm = ProjectManager.instance()
        projects = pm.projects

        tasks = []
        for project in projects:
            tasks.append(asyncio.async(project.close()))

        if tasks:
            done, _ = yield from asyncio.wait(tasks)
            for future in done:
                try:
                    future.result()
                except Exception as e:
                    log.error("Could not close project {}".format(e), exc_info=1)
                    continue

        # then shutdown the compute itself
        from gns3server.web.web_server import WebServer
        server = WebServer.instance()
        asyncio.async(server.shutdown_server())
        response.set_status(201)