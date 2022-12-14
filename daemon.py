#!/usr/bin/env python3
import requests
import pickle
import pathlib

import tornado.ioloop
import tornado.web
import tornado.gen
from utils import (
    response_start_tms_mitigation,
    response_patch_tms_mitigation,
    DEFAULT_MITIGATION_ID_TEMPLATES,
    DEFAULT_TMS_GROUPS,
)


DATA_PKL_FNAME = "netscout_data.pkl"
DATA = {}
BASE_ARBOR_API_URL = "_"
ARBOR_API_TOKEN = "_"
CONTENT_TYPE = "application/vnd.api+json"
STORED_MITIGATION_ID_TEMPLATES = DEFAULT_MITIGATION_ID_TEMPLATES
STORED_TMS_GROUPS = DEFAULT_TMS_GROUPS


def dump_data():
    with open(DATA_PKL_FNAME, "wb") as f:
        pickle.dump(DATA, f, protocol=pickle.HIGHEST_PROTOCOL)


def load_data():
    file = pathlib.Path(DATA_PKL_FNAME)
    if file.exists():
        with open(file, "rb") as f:
            return pickle.load(f)
    else:
        return {"mitigation_counter": 0, "keys": {}}


def delete_arbor_daemon_data():
    pathlib.Path(DATA_PKL_FNAME).unlink()


DATA = load_data()


def check_api_and_content_type(function):
    def wrapper(handler, **kwargs):
        handler.api_token = handler.request.headers.get("X-Arbux-APIToken", None)
        if (
            handler.api_token not in DATA["keys"].keys()
            and handler.api_token != ARBOR_API_TOKEN
        ):
            handler.write_error(
                400,
                [
                    {
                        "field": "X-Arbux-APIToken",
                        "message": "The provided authentication token is invalid.",
                        "code": "invalidAuthToken",
                    }
                ],
            )
            return
        function(handler, **kwargs)

    return wrapper


class CustomRequestHandler(tornado.web.RequestHandler):
    def write_error(self, status_code, errors):
        self.set_status(status_code)
        self.write({"message": "Authentication Failed", "errors": errors})
        self.finish()

    def get_from_arbor(self, endpoint=""):
        url = f"{BASE_ARBOR_API_URL}{endpoint}"
        response = requests.get(url, headers={"X-Arbux-APIToken": ARBOR_API_TOKEN})
        status_code = response.status_code
        self.set_status(status_code)
        if status_code not in [200, 201]:
            self.write(response.text)
            return

        self.write(response.json())
        self.finish()


class ArborHandler(CustomRequestHandler):
    @check_api_and_content_type
    def get(self):
        if self.api_token == ARBOR_API_TOKEN:
            self.get_from_arbor()
            return

        # Mocked response
        self.set_status(200)
        self.write(
            {
                "meta": {
                    "sp_version": "8.4.1",
                    "api": "SP",
                    "api_version": "4",
                    "sp_build_id": "ILNJ",
                },
                "links": {
                    "mitigation_template": "https://localhost:11443/api/sp/v4/mitigation_templates/",
                    "tms_port": "https://localhost:11443/api/sp/v4/tms_ports/",
                    "insight": "https://localhost:11443/api/sp/v4/insight/",
                    "tms_filter_list": "https://localhost:11443/api/sp/v4/tms_filter_lists/",
                    "mitigation": "https://localhost:11443/api/sp/v4/mitigations/",
                    "self": "https://localhost:11443/api/sp/v4/",
                    "learning_mitigation": "https://localhost:11443/api/sp/v4/learning_mitigations/",
                    "global_afsm_settings": "https://localhost:11443/api/sp/v4/global_afsm_settings",
                    "managed_object": "https://localhost:11443/api/sp/v4/managed_objects/",
                    "tms_filter_list_request": "https://localhost:11443/api/sp/v4/tms_filter_list_requests/",
                    "notification_group": "https://localhost:11443/api/sp/v4/notification_groups/",
                    "application": "https://localhost:11443/api/sp/v4/applications/",
                    "tms_group": "https://localhost:11443/api/sp/v4/tms_groups/",
                    "alert": "https://localhost:11443/api/sp/v4/alerts/",
                    "fingerprint": "https://localhost:11443/api/sp/v4/fingerprints/",
                    "device": "https://localhost:11443/api/sp/v4/devices/",
                    "router": "https://localhost:11443/api/sp/v4/routers/",
                    "shared_host_detection_settings": "https://localhost:11443/api/sp/v4/shared_host_detection_settings/",
                    "bgp_trap": "https://localhost:11443/api/sp/v4/bgp_traps/",
                    "configuration": "https://localhost:11443/api/sp/v4/config/",
                    "global_detection_settings": "https://localhost:11443/api/sp/v4/global_detection_settings",
                },
            }
        )
        self.finish()


class MitigationTemplatesHandler(CustomRequestHandler):
    # curl -H "X-Arbux-APIToken: justatoken" -H "Content-Type: application/vnd.api+json" -L http://localhost:8888/api/sp/mitigation_templates/?include=tms_group
    @check_api_and_content_type
    def get(self):
        if self.api_token == ARBOR_API_TOKEN:
            self.get_from_arbor("mitigation_templates/")
            return

        # Mocked response
        self.set_status(200)
        self.write(
            {
                "data": [
                    stored_template["data"]
                    for stored_template_id, stored_template in STORED_MITIGATION_ID_TEMPLATES.items()
                ]
            }
        )
        self.finish()


class MitigationTemplatesIdHandler(CustomRequestHandler):
    # curl -H "X-Arbux-APIToken: justatoken" -H "Content-Type: application/vnd.api+json" -L http://localhost:8888/api/sp/mitigation_templates/an_id?include=tms_group
    @check_api_and_content_type
    def get(self, template_id=None):
        if self.api_token == ARBOR_API_TOKEN:
            self.get_from_arbor(f"mitigation_templates/{template_id}")
            return

        # Mocked response
        if (
            template_id is None
            or str(template_id) not in STORED_MITIGATION_ID_TEMPLATES.keys()
        ):
            self.set_status(404)
            error_message = [
                {
                    "status": "404",
                    "meta": {
                        "sp_version": "8.4.1",
                        "api": "SP",
                        "api_version": "4",
                        "sp_build_id": "ILNJ",
                    },
                    "detail": f"Resource {template_id} could not be found.",
                    "title": "Missing resource error.",
                }
            ]
            self.write({"errors": error_message})
            self.finish()
            return

        self.set_status(200)
        self.write(STORED_MITIGATION_ID_TEMPLATES[str(template_id)])


class TmsGroupsHandler(CustomRequestHandler):
    # curl -H "X-Arbux-APIToken: justatoken" -H "Content-Type: application/vnd.api+json" -L http://localhost:8888/api/sp/tms_groups/
    @check_api_and_content_type
    def get(self):
        if self.api_token == ARBOR_API_TOKEN:
            self.get_from_arbor("tms_groups/")
            return

        # Mocked response
        self.set_status(200)
        self.write(STORED_TMS_GROUPS)


class MitigationsHandler(CustomRequestHandler):
    # curl -H "X-Arbux-APIToken: justatoken" -H "Content-Type: application/vnd.api+json" -L http://localhost:8888/api/sp/mitigations?include=mitigation_template,tms_groups
    @check_api_and_content_type
    def get(self):
        if self.api_token == ARBOR_API_TOKEN:
            self.get_from_arbor("mitigations/")
            return

        # Mocked response
        self.set_status(200)
        mitigations = [
            v["data"] for _, v in DATA["keys"][self.api_token]["mitigations"].items()
        ]
        self.write({"data": mitigations})
        self.finish()

    # curl -H "X-Arbux-APIToken: justatoken" -H "Content-Type: application/vnd.api+json" -d @addtmsmit.json -L http://localhost:8888/api/sp/mitigations/ -X POST
    @check_api_and_content_type
    def post(self):
        data = tornado.escape.json_decode(self.request.body)
        DATA["mitigation_counter"] += 1
        mitigation = response_start_tms_mitigation(data, DATA["mitigation_counter"])
        mitigation_id = mitigation["data"]["id"]
        DATA["keys"][self.api_token]["mitigations"][mitigation_id] = mitigation
        dump_data()
        self.set_status(201)
        self.write(mitigation)


class MitigationsIdHandler(CustomRequestHandler):
    # curl -H "X-Arbux-APIToken: justatoken" -H "Content-Type: application/vnd.api+json" -L http://localhost:8888/api/sp/mitigations/tms-1234?include=mitigation_template,tms_group
    @check_api_and_content_type
    def get(self, mitigation_id):
        if self.api_token == ARBOR_API_TOKEN:
            self.get_from_arbor(f"mitigations/{mitigation_id}")
            return

        # Mocked response
        mitigation = (
            DATA["keys"]
            .get(self.api_token, {})
            .get("mitigations", {})
            .get(mitigation_id)
        )
        if mitigation is None:
            self.set_status(400)
            self.write(f"Mitigation {mitigation_id} does not exist")
            return

        self.set_status(200)
        self.write(mitigation)
        self.finish()

    # curl -H "X-Arbux-APIToken: justatoken" -H "Content-Type: application/vnd.api+json" -d @stopmit.json -L http://localhost:8888/api/sp/mitigations/tms-1234 -X PATCH
    @check_api_and_content_type
    def patch(self, mitigation_id=""):
        patch_data = tornado.escape.json_decode(self.request.body)
        mitigation = (
            DATA["keys"]
            .get(self.api_token, {})
            .get("mitigations", {})
            .get(mitigation_id)
        )
        if mitigation is None:
            self.write(400)
            self.write(f"Mitigation {mitigation_id} does not exist")
            return

        patched = response_patch_tms_mitigation(patch_data, mitigation)
        self.set_status(200)
        self.write(patched)

    @check_api_and_content_type
    def delete(self, mitigation_id=None):
        if (
            mitigation_id is not None
            and mitigation_id not in DATA["keys"][self.api_token]["mitigations"]
        ):
            self.write_error(400, f"Id {mitigation_id} does not exist")
            return

        DATA["keys"][self.api_token]["mitigations"].pop(mitigation_id)
        dump_data()
        self.set_status(204)


class ApiKeyHandler(tornado.web.RequestHandler):
    def post(self):
        data = tornado.escape.json_decode(self.request.body)
        new_api_key = data.get("api_token")

        if new_api_key is None:
            self.set_status(400)
            self.write("'api_token' not specified.")
            return

        if new_api_key in DATA["keys"]:
            self.set_status(400)
            self.write("Api key already exists.")
            return

        DATA["keys"][new_api_key] = {"mitigations": {}}
        dump_data()
        self.set_status(200)
        self.finish()

    def delete(self):
        data = tornado.escape.json_decode(self.request.body)
        api_key = data.get("api_token")

        if api_key not in DATA["keys"]:
            self.set_status(400)
            self.write("Api key does not exist.")
            return
        DATA["keys"].pop(api_key)
        dump_data()
        self.set_status(200)
        self.finish()

    def get(self):
        self.set_status(200)
        self.write({"data": list(DATA["keys"].keys())})
        self.finish()


def make_app():
    return tornado.web.Application(
        [
            (r"/api/sp/", ArborHandler),
            (r"/api/sp/mitigation_templates/", MitigationTemplatesHandler),
            (
                r"/api/sp/mitigation_templates/(?P<template_id>\w+)",
                MitigationTemplatesIdHandler,
            ),
            (r"/api/sp/tms_groups/", TmsGroupsHandler),
            (r"/api/sp/mitigations/?", MitigationsHandler),
            (r"/api/sp/mitigations/(?P<mitigation_id>[\w'-]+)", MitigationsIdHandler),
            (r"/api/key", ApiKeyHandler),
        ]
    )


def start_server():
    ioloop = tornado.ioloop.IOLoop.current()
    app = make_app()
    app.listen(8888)
    ioloop.start()


if __name__ == "__main__":
    start_server()
