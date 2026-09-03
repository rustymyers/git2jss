#!/usr/bin/env python3
import getpass
import requests
from defusedxml import ElementTree as eTree
from defusedxml import minidom
import os
import argparse
import urllib3
import configparser

# Suppress the warning in dev
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# https://github.com/lazymutt/Jamf-Pro-API-Sampler/blob/5f8efa92911271248f527e70bd682db79bc600f2/jamf_duplicate_detection.py#L99
def get_uapi_token():
    """fetches api token"""
    jamf_test_url = url + "/api/v1/auth/token"
    response = requests.post(url=jamf_test_url, auth=(username, password), timeout=5)
    response_json = response.json()
    return response_json["token"]


def invalidate_uapi_token(uapi_token):
    """invalidates api token"""
    jamf_test_url = url + "/api/v1/auth/invalidate-token"
    headers = {"Accept": "*/*", "Authorization": "Bearer " + uapi_token}
    _ = requests.post(url=jamf_test_url, headers=headers, timeout=5)


RESOURCE_CONFIG = {
    "ea": ("computerextensionattributes", "extension_attributes", "input_type/script"),
    "script": ("scripts", "scripts", "script_contents"),
}


def request_xml(endpoint, token):
    response = requests.get(
        url + endpoint,
        headers={
            "Accept": "application/xml",
            "Content-Type": "application/xml",
            "Authorization": "Bearer " + token,
        },
        verify=args.do_not_verify_ssl,
        timeout=5,
    )
    response.raise_for_status()
    return eTree.fromstring(response.content)


def get_resource_ids(resource, token):
    try:
        tree = request_xml("/JSSResource/%s" % resource, token)
    except requests.HTTPError as error:
        print(
            "Something went wrong with the request, check your password and "
            "privileges, URL, and HTTP status: %s" % error
        )
        exit(1)
    return [element.text for element in tree.findall(".//id")]


def script_extension(script, resource_name):
    extensions = {
        "#!/bin/sh": ".sh",
        "#!/usr/bin/env sh": ".sh",
        "#!/bin/bash": ".sh",
        "#!/usr/bin/env bash": ".sh",
        "#!/bin/zsh": ".sh",
        "#!/usr/bin/python": ".py",
        "#!/usr/bin/env python": ".py",
        "#!/usr/bin/perl": ".pl",
        "#!/usr/bin/ruby": ".rb",
    }
    for interpreter, extension in extensions.items():
        if script.startswith(interpreter):
            return extension
    print("No interpreter directive found for: ", resource_name)
    return ".sh"


def prepare_resource(tree, mode, script_xml, resource_path):
    script_node = tree.find(script_xml)
    script = eTree.tostring(script_node, encoding="unicode", method="text").replace(
        "\r", ""
    )
    extension = script_extension(script, tree.find("name").text)
    with open(os.path.join(resource_path, "%s%s" % (mode, extension)), "w") as handle:
        handle.write(script)

    if script_node is not None:
        script_node.clear()
    for tag in ("id", "script_contents_encoded", "filename"):
        node = tree.find(tag)
        if node is not None:
            tree.remove(node)


def save_resource(tree, mode, script_xml, resource_path, get_script):
    if get_script:
        prepare_resource(tree, mode, script_xml, resource_path)
    xml = minidom.parseString(
        eTree.tostring(tree, encoding="unicode", method="xml")
    ).toprettyxml(indent="   ")
    with open(os.path.join(resource_path, "%s.xml" % mode), "w") as handle:
        handle.write(xml)


def download_resource(resource_id, mode, resource, download_path, script_xml, token, overwrite):
    tree = request_xml("/JSSResource/%s/id/%s" % (resource, resource_id), token)
    resource_name = tree.find("name").text
    get_script = True
    if mode == "ea" and tree.find("input_type/type").text != "script":
        print("No script found in: %s" % resource_name)
        get_script = False

    resource_path = os.path.join(export_path, download_path, resource_name)
    if os.path.exists(resource_path):
        print("Resource is already in the repo: ", resource_name)
        if not overwrite:
            print("\tSkipping: ", resource_name)
            return
    else:
        os.makedirs(resource_path)

    print("Saving: ", resource_name)
    save_resource(tree, mode, script_xml, resource_path, get_script)


def download_scripts(mode, overwrite=None):
    """Download scripts or script-based extension attributes from Jamf Pro."""
    try:
        resource, download_path, script_xml = RESOURCE_CONFIG[mode]
    except KeyError:
        raise ValueError("mode must be 'ea' or 'script'") from None

    token = get_uapi_token()
    for resource_id in get_resource_ids(resource, token):
        download_resource(
            resource_id,
            mode,
            resource,
            download_path,
            script_xml,
            token,
            overwrite,
        )
    invalidate_uapi_token(token)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Download Scripts from Jamf")
    parser.add_argument("--url")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--export_path")
    parser.add_argument("--overwrite", action="store_true")  # Overwrites existing files
    parser.add_argument(
        "--do_not_verify_ssl", action="store_false"
    )  # Skips SSL verification
    return parser.parse_args()


def load_config(default_export_path):
    config = {
        "username": None,
        "password": "",
        "url": None,
        "export_path": default_export_path,
    }
    CONFIG_FILE_LOCATIONS = ["jamfapi.cfg", os.path.expanduser("~/jamfapi.cfg")]
    CONFIG_FILE = ""
    config_parser = configparser.ConfigParser()
    for config_path in CONFIG_FILE_LOCATIONS:
        if os.path.exists(config_path):
            print("Found Config: {0}".format(config_path))
            CONFIG_FILE = config_path

    if CONFIG_FILE != "":
        config_parser.read(CONFIG_FILE)
        config_options = {
            "username": ("username", "Can't find username in configfile"),
            "password": ("password", "Can't find password in configfile"),
            "url": ("server", "Can't find url in configfile"),
            "export_path": ("export_path", "Can't find export_path in config"),
        }
        for setting, (option, error_message) in config_options.items():
            try:
                config[setting] = config_parser.get("jss", option)
            except configparser.NoOptionError:
                print(error_message)
    return config


def apply_cli_settings(config, parsed_args):
    if parsed_args.password:
        config["password"] = parsed_args.password
    elif not config["password"]:
        config["password"] = getpass.getpass()

    if parsed_args.export_path:
        config["export_path"] = parsed_args.export_path
    if parsed_args.url:
        config["url"] = parsed_args.url
    if parsed_args.username:
        config["username"] = parsed_args.username
    return config


def main():
    global args, export_path, password, url, username

    default_export_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
    parsed_args = parse_arguments()
    config = load_config(default_export_path)
    config = apply_cli_settings(config, parsed_args)

    args = parsed_args
    export_path = config["export_path"]
    password = config["password"]
    url = config["url"]
    username = config["username"]

    download_scripts(overwrite=args.overwrite, mode="ea")
    download_scripts(overwrite=args.overwrite, mode="script")


if __name__ == "__main__":
    main()
