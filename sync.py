#!/usr/bin/env python3
# pylint: disable=missing-docstring,invalid-name

"""Synchronize Jamf Pro scripts and computer extension attributes from a repository."""

from __future__ import annotations

import argparse
import asyncio
import configparser
import getpass
import logging
import os
import subprocess
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence
from urllib.parse import quote

import aiohttp
import requests
from defusedxml import ElementTree as eTree

try:
    import uvloop
except ImportError:
    uvloop = None


logging.basicConfig(
    level=logging.DEBUG,
    format="%(levelname)7s: %(message)s",
    stream=sys.stderr,
)
LOG = logging.getLogger(__name__)

SLACK_EMOJI = ":white_check_mark: "
SUPPORTED_SCRIPT_EXTENSIONS = {"sh", "py", "pl", "swift", "rb"}
SUPPORTED_EA_EXTENSIONS = {"sh", "py", "pl", "swift", "rb"}
SUCCESS_STATUSES = {200, 201}


@dataclass(frozen=True)
class AppSettings:
    """Resolved application settings."""

    url: str
    username: str
    password: str
    sync_path: Path


@dataclass
class RuntimeContext:
    """Mutable state shared by one synchronization run."""

    args: argparse.Namespace
    settings: AppSettings
    token: str = ""
    changed_scripts: list[str] = field(default_factory=list)
    changed_ext_attrs: list[str] = field(default_factory=list)
    categories: set[str] = field(default_factory=set)

    @property
    def url(self) -> str:
        return self.settings.url

    @property
    def username(self) -> str:
        return self.settings.username

    @property
    def password(self) -> str:
        return self.settings.password

    @property
    def sync_path(self) -> Path:
        return self.settings.sync_path


class JamfSync:
    """Manage asynchronous Jamf Classic API synchronization operations."""

    def __init__(self, context: RuntimeContext):
        self.ctx = context
        self.session: aiohttp.ClientSession | None = None
        self.semaphore = asyncio.BoundedSemaphore(context.args.limit)

    @property
    def headers(self) -> dict[str, str]:
        return {
            "Accept": "application/xml",
            "Content-Type": "application/xml",
            "Authorization": f"Bearer {self.ctx.token}",
        }

    async def run(self) -> None:
        """Create the HTTP session and run all synchronization operations."""
        connector = aiohttp.TCPConnector(
            ssl=False if self.ctx.args.do_not_verify_ssl else None
        )
        timeout = aiohttp.ClientTimeout(total=self.ctx.args.timeout)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self.headers,
        ) as session:
            self.session = session
            self.ctx.categories = await self.get_existing_categories()
            LOG.debug("Found %d Jamf categories", len(self.ctx.categories))

            script_results, ea_results = await asyncio.gather(
                self.upload_scripts(),
                self.upload_extension_attributes(),
            )

            failures = [
                *[name for name, status in script_results if status not in SUCCESS_STATUSES],
                *[name for name, status in ea_results if status not in SUCCESS_STATUSES],
            ]
            if failures:
                raise RuntimeError(
                    "One or more Jamf objects failed to upload: " + ", ".join(failures)
                )

    def require_session(self) -> aiohttp.ClientSession:
        if self.session is None:
            raise RuntimeError("JamfSync session has not been initialized")
        return self.session

    async def request(self, method: str, endpoint: str, **kwargs) -> tuple[int, str]:
        """Perform one concurrency-limited Jamf request and return status/body."""
        session = self.require_session()
        url = f"{self.ctx.url}{endpoint}"

        async with self.semaphore:
            async with session.request(method, url, **kwargs) as response:
                body = await response.text()
                if self.ctx.args.verbose:
                    LOG.debug("%s %s returned HTTP %s", method, endpoint, response.status)
                return response.status, body

    async def get_existing_categories(self) -> set[str]:
        status, body = await self.request("GET", "/JSSResource/categories")
        if status not in SUCCESS_STATUSES:
            LOG.warning("Unable to retrieve Jamf categories: HTTP %s", status)
            return set()

        root = eTree.fromstring(body)
        return {
            category.text
            for category in root.findall("category/name")
            if category.text
        }

    async def upload_scripts(self) -> list[tuple[str, int]]:
        scripts = self._selected_directories(
            root=self.ctx.sync_path / "scripts",
            changed_names=self.ctx.changed_scripts,
            object_label="scripts",
        )

        if not scripts:
            LOG.info("No scripts selected for upload")
            return []

        results = await asyncio.gather(
            *(self.upload_script(script_name) for script_name in scripts)
        )
        return list(zip(scripts, results))

    async def upload_script(self, script_name: str) -> int:
        script_dir = self.ctx.sync_path / "scripts" / script_name
        script_file = self._first_file_with_extensions(
            script_dir,
            SUPPORTED_SCRIPT_EXTENSIONS,
        )

        if script_file is None:
            LOG.warning("No script file found in scripts/%s", script_name)
            return 0

        script_contents = script_file.read_text(encoding="utf-8")
        template = await self.get_script_template(script_name)
        name = self._ensure_name(template, script_name)

        contents_element = template.find("script_contents")
        if contents_element is None:
            contents_element = eTree.SubElement(template, "script_contents")
        contents_element.text = script_contents

        status = await self._create_or_update(
            resource="scripts",
            name=name,
            template=template,
        )
        self._log_upload_result("script", name, status)
        return status

    async def get_script_template(self, script_name: str):
        object_dir = self.ctx.sync_path / "scripts" / script_name
        template = await self._load_local_or_remote_template(
            object_dir=object_dir,
            fallback_path=self.ctx.sync_path / "templates" / "script.xml",
            resource="scripts",
            lookup_name=script_name,
        )

        self._normalize_category(template, add_none=False)
        self._ensure_name(template, script_name)
        self._log_xml(template)
        return template

    async def upload_extension_attributes(self) -> list[tuple[str, int]]:
        extension_attributes = self._selected_directories(
            root=self.ctx.sync_path / "extension_attributes",
            changed_names=self.ctx.changed_ext_attrs,
            object_label="extension attributes",
        )

        if not extension_attributes:
            LOG.info("No extension attributes selected for upload")
            return []

        results = await asyncio.gather(
            *(
                self.upload_extension_attribute(ext_attr)
                for ext_attr in extension_attributes
            )
        )
        return list(zip(extension_attributes, results))

    async def upload_extension_attribute(self, ext_attr: str) -> int:
        extension_attribute_dir = (
            self.ctx.sync_path / "extension_attributes" / ext_attr
        )
        script_file = self._first_file_with_extensions(
            extension_attribute_dir,
            SUPPORTED_EA_EXTENSIONS,
        )

        if script_file is None:
            LOG.warning(
                "No script file found in extension_attributes/%s; "
                "uploading the XML template without a script",
                ext_attr,
            )
            script_contents = None
        else:
            script_contents = script_file.read_text(encoding="utf-8")

        template = await self.get_ea_template(ext_attr)
        name = self._ensure_name(template, ext_attr)

        if script_contents is not None:
            script_element = template.find("input_type/script")
            if script_element is None:
                input_type = template.find("input_type")
                if input_type is None:
                    input_type = eTree.SubElement(template, "input_type")
                script_element = eTree.SubElement(input_type, "script")
            script_element.text = script_contents

        status = await self._create_or_update(
            resource="computerextensionattributes",
            name=name,
            template=template,
        )
        self._log_upload_result("extension attribute", name, status)
        return status

    async def get_ea_template(self, ext_attr: str):
        object_dir = self.ctx.sync_path / "extension_attributes" / ext_attr
        template = await self._load_local_or_remote_template(
            object_dir=object_dir,
            fallback_path=self.ctx.sync_path / "templates" / "ea.xml",
            resource="computerextensionattributes",
            lookup_name=ext_attr,
        )

        self._normalize_category(template, add_none=True)
        self._ensure_name(template, ext_attr)
        self._log_xml(template)
        return template

    async def _load_local_or_remote_template(
        self,
        object_dir: Path,
        fallback_path: Path,
        resource: str,
        lookup_name: str,
    ):
        xml_files = sorted(
            path for path in object_dir.iterdir() if path.is_file() and path.suffix.lower() == ".xml"
        )

        if xml_files:
            return eTree.parse(str(xml_files[0])).getroot()

        endpoint = f"/JSSResource/{resource}/name/{quote(lookup_name, safe='')}"
        status, body = await self.request("GET", endpoint)

        if status == 200:
            return eTree.fromstring(body)

        if not fallback_path.is_file():
            raise FileNotFoundError(f"Missing fallback template: {fallback_path}")

        return eTree.parse(str(fallback_path)).getroot()

    async def _create_or_update(self, resource: str, name: str, template) -> int:
        encoded_name = quote(name, safe="")
        lookup_endpoint = f"/JSSResource/{resource}/name/{encoded_name}"
        lookup_status, _ = await self.request("GET", lookup_endpoint)
        payload = eTree.tostring(template, encoding="utf-8")

        if lookup_status == 200:
            status, body = await self.request("PUT", lookup_endpoint, data=payload)
        elif lookup_status == 404:
            create_endpoint = f"/JSSResource/{resource}/id/0"
            status, body = await self.request("POST", create_endpoint, data=payload)
        else:
            LOG.error(
                "Unable to determine whether %s '%s' exists: HTTP %s",
                resource,
                name,
                lookup_status,
            )
            return lookup_status

        if status not in SUCCESS_STATUSES and body:
            LOG.error("Jamf response for %s '%s': %s", resource, name, body)
        return status

    def _selected_directories(
        self,
        root: Path,
        changed_names: Sequence[str],
        object_label: str,
    ) -> list[str]:
        if self.ctx.args.update_all:
            LOG.info("Copying all %s", object_label)
            return sorted(path.name for path in root.iterdir() if path.is_dir())

        if not changed_names:
            return []

        changed_set = set(changed_names)
        return sorted(
            path.name
            for path in root.iterdir()
            if path.is_dir() and path.name in changed_set
        )

    @staticmethod
    def _first_file_with_extensions(
        directory: Path,
        extensions: set[str],
    ) -> Path | None:
        matches = sorted(
            path
            for path in directory.iterdir()
            if path.is_file() and path.suffix.lower().lstrip(".") in extensions
        )
        return matches[0] if matches else None

    @staticmethod
    def _ensure_name(template, fallback_name: str) -> str:
        name_element = template.find("name")
        if name_element is None:
            name_element = eTree.SubElement(template, "name")
        if not name_element.text:
            name_element.text = fallback_name
        return name_element.text

    def _normalize_category(self, template, add_none: bool) -> None:
        category = template.find("category")
        if category is None or not category.text:
            return
        if category.text in self.ctx.categories:
            return

        invalid_category = category.text
        template.remove(category)
        if add_none:
            eTree.SubElement(template, "category").text = "None"

        LOG.warning(
            'Category "%s" does not exist in Jamf; using %s',
            invalid_category,
            '"None"' if add_none else "no category",
        )

    def _log_xml(self, template) -> None:
        if self.ctx.args.verbose:
            LOG.debug("Template XML: %s", eTree.tostring(template, encoding="unicode"))

    @staticmethod
    def _log_upload_result(object_type: str, name: str, status: int) -> None:
        if status in SUCCESS_STATUSES:
            LOG.info("Uploaded %s: %s", object_type, name)
        else:
            LOG.error("Error uploading %s '%s': HTTP %s", object_type, name, status)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync repository with Jamf Pro")
    parser.add_argument("--url")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--sync_path")
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--do_not_verify_ssl",
        action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument("--update_all", action="store_true")
    parser.add_argument("--jenkins", action="store_true")
    return parser.parse_args()


def find_config_file() -> Path | None:
    config_locations = (
        Path("jamfapi.cfg"),
        Path.home() / "jamfapi.cfg",
    )

    for config_path in config_locations:
        if config_path.is_file():
            LOG.info("Found configuration file: %s", config_path)
            return config_path
    return None


def read_config_file(config_path: Path | None) -> dict[str, str | None]:
    settings: dict[str, str | None] = {
        "username": None,
        "url": None,
        "sync_path": None,
    }
    if config_path is None:
        return settings

    config = configparser.ConfigParser()
    config.read(config_path)
    if not config.has_section("jss"):
        LOG.warning("Configuration file %s has no [jss] section", config_path)
        return settings

    settings["username"] = config.get("jss", "username", fallback=None)
    settings["password"] = config.get("jss", "password", fallback=None)
    settings["url"] = config.get("jss", "server", fallback=None)
    settings["sync_path"] = config.get("jss", "sync_path", fallback=None)
    return settings


def first_value(*values):
    return next((value for value in values if value not in (None, "")), None)


def resolve_settings(args: argparse.Namespace) -> AppSettings:
    config = read_config_file(find_config_file())

    username = first_value(args.username, os.getenv("JAMF_API_USER"), config["username"])
    password = first_value(args.password, os.getenv("JAMF_API_PASS"), config["password"])
    url = first_value(args.url, os.getenv("MDM_URL"), config["url"])
    sync_path_value = first_value(
        args.sync_path,
        config["sync_path"],
        str(Path(__file__).resolve().parent),
    )

    if not username:
        raise ValueError("Missing required Jamf setting: username")
    if not url:
        raise ValueError("Missing required Jamf setting: url")
    if not password:
        password = getpass.getpass(f"Password for {username}: ")

    settings = AppSettings(
        url=str(url).rstrip("/"),
        username=str(username),
        password=str(password),
        sync_path=Path(str(sync_path_value)).expanduser().resolve(),
    )
    validate_settings(settings)
    return settings


def validate_settings(settings: AppSettings) -> None:
    if not settings.sync_path.is_dir():
        raise ValueError(f"Sync path is not a directory: {settings.sync_path}")

    required_directories = ("scripts", "extension_attributes", "templates")
    missing = [
        name
        for name in required_directories
        if not (settings.sync_path / name).is_dir()
    ]
    if missing:
        raise ValueError(
            "Sync path is missing required directories: " + ", ".join(missing)
        )


def get_uapi_token(settings: AppSettings) -> str:
    response = requests.post(
        f"{settings.url}/api/v1/auth/token",
        auth=(settings.username, settings.password),
        timeout=10,
    )
    response.raise_for_status()
    response_json = response.json()
    token = response_json.get("token")
    if not token:
        raise ValueError("Jamf token response did not contain a token")
    return token


def invalidate_uapi_token(settings: AppSettings, token: str) -> None:
    response = requests.post(
        f"{settings.url}/api/v1/auth/invalidate-token",
        headers={"Accept": "*/*", "Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if response.status_code not in (200, 204):
        LOG.warning("Unable to invalidate Jamf token: HTTP %s", response.status_code)


def git_changed_files(jenkins: bool) -> list[str]:
    if jenkins:
        previous_commit = os.getenv("GIT_PREVIOUS_COMMIT")
        current_commit = os.getenv("GIT_COMMIT")
        if not previous_commit or not current_commit:
            raise ValueError(
                "Jenkins mode requires GIT_PREVIOUS_COMMIT and GIT_COMMIT"
            )
        command = ["git", "diff", "--name-only", previous_commit, current_commit]
    else:
        result = subprocess.run(
            ["git", "log", "-2", "--pretty=format:%H"],
            check=True,
            capture_output=True,
            text=True,
        )
        commits = [line for line in result.stdout.splitlines() if line]
        if len(commits) < 2:
            LOG.warning("Fewer than two Git commits found; no changed files selected")
            return []
        command = ["git", "diff", "--name-only", commits[1], commits[0]]

    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def check_for_changes(ctx: RuntimeContext) -> None:
    for changed_path in git_changed_files(ctx.args.jenkins):
        parts = Path(changed_path).parts
        if len(parts) < 2:
            continue

        if parts[0] == "extension_attributes":
            if parts[1] not in ctx.changed_ext_attrs:
                ctx.changed_ext_attrs.append(parts[1])
        elif parts[0] == "scripts":
            if parts[1] not in ctx.changed_scripts:
                ctx.changed_scripts.append(parts[1])


def format_jenkins_value(items: Sequence[str]) -> str:
    if not items:
        return "None"
    return "\\n\\\n".join(f"{SLACK_EMOJI}{item}" for item in items) + "\\n"


def write_jenkins_file(ctx: RuntimeContext) -> None:
    contents = (
        f"eas={format_jenkins_value(ctx.changed_ext_attrs)}\n"
        f"scripts={format_jenkins_value(ctx.changed_scripts)}"
    )
    Path("jenkins.properties").write_text(contents, encoding="utf-8")


def configure_runtime(args: argparse.Namespace) -> None:
    if args.verbose:
        warnings.simplefilter("always", ResourceWarning)


def run() -> None:
    args = parse_arguments()
    configure_runtime(args)
    settings = resolve_settings(args)
    ctx = RuntimeContext(args=args, settings=settings)

    check_for_changes(ctx)
    LOG.info("Changed Extension Attributes: %s", ctx.changed_ext_attrs or "None")
    LOG.info("Changed Scripts: %s", ctx.changed_scripts or "None")

    if args.jenkins:
        write_jenkins_file(ctx)

    try:
        ctx.token = get_uapi_token(settings)
        asyncio.run(JamfSync(ctx).run(), debug=args.verbose)
    finally:
        if ctx.token:
            invalidate_uapi_token(settings, ctx.token)


if __name__ == "__main__":
    if uvloop is not None:
        uvloop.install()

    try:
        run()
    except KeyboardInterrupt:
        LOG.warning("Synchronization interrupted by user")
        sys.exit(130)
    except (
        ValueError,
        FileNotFoundError,
        requests.RequestException,
        aiohttp.ClientError,
        subprocess.CalledProcessError,
        RuntimeError,
    ) as error:
        LOG.error("%s", error)
        sys.exit(1)
    except Exception:
        LOG.exception("Unexpected synchronization failure")
        sys.exit(1)
