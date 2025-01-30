import asyncio
import hashlib
import json
import logging
import mimetypes
import os
import re
from asyncio.exceptions import TimeoutError
from string import punctuation, whitespace
from time import time
from typing import List

import aiofiles
import aiohttp
from aiohttp import ClientConnectorError, ServerDisconnectedError

PROTOCOL = "https://"
ILLEGAL_PATH_CHARS = punctuation.replace(".", "") + whitespace

DYNAMIC_PART_MOCK = "cu-crawler"

INPUT_FILENAME = os.environ.get("INPUT_FILENAME", "tracked_links.txt")
INPUT_RES_FILENAME = os.environ.get("INPUT_FILENAME", "tracked_res_links.txt")
OUTPUT_FOLDER = os.environ.get("OUTPUT_FOLDER", "data/")
OUTPUT_SITES_FOLDER = os.path.join(
    OUTPUT_FOLDER, os.environ.get("OUTPUT_SITES_FOLDER", "web/")
)
OUTPUT_RESOURCES_FOLDER = os.path.join(
    OUTPUT_FOLDER, os.environ.get("OUTPUT_RESOURCES_FOLDER", "web_res/")
)

PAGE_GENERATION_TIME_REGEX = r"<!-- page generated in .+ -->"
PAGE_API_HASH_REGEX = r"\?hash=[a-z0-9]+"
PAGE_API_HASH_TEMPLATE = f"?hash={DYNAMIC_PART_MOCK}"
TON_RATE_REGEX = r'"tonRate":"[.0-9]+"'
TON_RATE_TEMPLATE = f'"tonRate":"{DYNAMIC_PART_MOCK}"'
PASSPORT_SSID_REGEX = r"passport_ssid=[a-z0-9]+_[a-z0-9]+_[a-z0-9]+"
PASSPORT_SSID_TEMPLATE = f"passport_ssid={DYNAMIC_PART_MOCK}"
NONCE_REGEX = r'nonce="[a-z0-9]+"'
NONCE_TEMPLATE = f'nonce="{DYNAMIC_PART_MOCK}"'
CSRF_TOKEN_REGEX = r'name="csrfmiddlewaretoken" value="\w+"'
CSRF_TOKEN_TEMPLATE = f'name="csrfmiddlewaretoken" value="{DYNAMIC_PART_MOCK}"'
PROXY_CONFIG_SUB_NET_REGEX = r"\d+\.\d+:8888;"
PROXY_CONFIG_SUB_NET_TEMPLATE = "X.X:8888;"
TRANSLATE_SUGGESTION_REGEX = r'<div class="tr-value-suggestion">(.?)+</div>'
SPARKLE_SIG_REGEX = r";sig=(.*?);"
SPARKLE_SE_REGEX = r";se=(.*?);"
SPARKLE_SIG_TEMPLATE = f";sig={DYNAMIC_PART_MOCK};"
SPARKLE_SE_TEMPLATE = f";se={DYNAMIC_PART_MOCK};"

STEL_DEV_LAYER = 190

# unsecure but so simple
CONNECTOR = aiohttp.TCPConnector(ssl=False, force_close=True, limit=300)
TIMEOUT = aiohttp.ClientTimeout(total=10)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:99.0) Gecko/20100101 Firefox/99.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Cookie": f"stel_ln=en; stel_dev_layer={STEL_DEV_LAYER}",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
    "TE": "trailers",
}

logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


def get_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def download_file(url: str, path: str, session: aiohttp.ClientSession):
    async with session.get(url) as response:
        if response.status != 200:
            return

        content = await response.read()

    async with aiofiles.open(path, mode="wb") as f:
        await f.write(content)


async def track_additional_files(
    files_to_track: List[str],
    input_dir_name: str,
    output_dir_name: str,
    encoding="utf-8",
    save_hash_only=False,
):
    kwargs = {"mode": "r", "encoding": encoding}
    if save_hash_only:
        kwargs["mode"] = "rb"
        del kwargs["encoding"]

    for file in files_to_track:
        async with aiofiles.open(
            os.path.join(input_dir_name, file), **kwargs
        ) as r_file:
            content = await r_file.read()

        if save_hash_only:
            content = get_hash(content)
        else:
            content = re.sub(r'id=".*"', 'id="tgcrawl"', content)

        filename = os.path.join(output_dir_name, file)
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        async with aiofiles.open(filename, "w", encoding="utf-8") as w_file:
            await w_file.write(content)


def parse_string_with_possible_json(input_string) -> dict:
    # chat gtp powered code:
    try:
        # Attempt to parse the entire input string as JSON
        json_object = json.loads(input_string)
    except json.JSONDecodeError as e:
        # Regular expression to find JSON objects within the string
        json_regex = r"{[^{}]*}"
        matches = re.findall(json_regex, input_string)

        if matches:
            # Use the first match as the extracted JSON
            json_object = json.loads(matches[0])
        else:
            raise ValueError("No JSON found within the input string.")

    return json_object


def is_hashable_only_content_type(content_type) -> bool:
    hashable_only_content_types = (
        "png",
        "jpeg",
        "x-icon",
        "gif",
        "mp4",
        "webm",
        "zip",
        "stream",
    )

    for hashable_only_content_type in hashable_only_content_types:
        if hashable_only_content_type in content_type:
            return True

    return False


class RetryError(Exception): ...


async def crawl(url: str, session: aiohttp.ClientSession, output_dir: str):
    while True:
        try:
            await _crawl(url, session, output_dir)
        except (
            RetryError,
            ServerDisconnectedError,
            TimeoutError,
            ClientConnectorError,
        ):
            logger.warning(f"Client or timeout error. Retrying {url}")
        else:
            break


async def _crawl(url: str, session: aiohttp.ClientSession, output_dir: str):
    logger.info(f"Process {url}")
    async with session.get(
        f"{PROTOCOL}{url}", allow_redirects=False, timeout=TIMEOUT, headers=HEADERS
    ) as response:
        if 499 < response.status < 600:
            msg = f"Error 5XX. Retrying {url}"
            logger.warning(msg)
            raise RetryError(msg)

        if response.status not in {200, 304}:
            if response.status != 302:
                content = await response.text()
                logger.debug(
                    f"Skip {url} because status code == {response.status}. Content: {content}"
                )
            return

        # bypass external slashes and so on
        url_parts = [p for p in url.split("/") if p not in ILLEGAL_PATH_CHARS]

        content_type = response.content_type

        # handle pure domains and html pages without ext in url as html do enable syntax highlighting
        page_type, _ = mimetypes.guess_type(url)

        ext = ""
        if page_type:
            ext = mimetypes.guess_extension(page_type) or ""
            if ext != "" and url.endswith(ext):
                ext = ""

        if url.endswith(".tl"):
            page_type = "text/plain"

        if page_type is None or len(url_parts) == 1:
            ext = ".html"
            content_type = "text/html"

        is_hashable_only = is_hashable_only_content_type(content_type)
        # amazing dirt for media files like
        # telegram.org/file/811140591/1/q7zZHjgES6s/9d121a89ffb0015837
        # with response content type HTML instead of image.
        # shame on you.
        # sometimes it returns a correct type.
        # noice load balancing
        is_sucking_file = "/file/" in url and "text" in content_type

        # I don't add ext by content type for images, and so on cuz TG servers suck.
        # Some servers do not return a correct content type.
        # Some servers do...
        if is_hashable_only or is_sucking_file:
            ext = ".sha256"

        filename = os.path.join(output_dir, *url_parts) + ext
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        if is_sucking_file or is_hashable_only:
            content = await response.read()
            async with aiofiles.open(filename, "w", encoding="utf-8") as f:
                await f.write(get_hash(content))
            return

        content = await response.text(encoding="UTF-8")

        content = re.sub(PAGE_GENERATION_TIME_REGEX, "", content)
        content = re.sub(PAGE_API_HASH_REGEX, PAGE_API_HASH_TEMPLATE, content)
        content = re.sub(PASSPORT_SSID_REGEX, PASSPORT_SSID_TEMPLATE, content)
        content = re.sub(NONCE_REGEX, NONCE_TEMPLATE, content)
        content = re.sub(
            PROXY_CONFIG_SUB_NET_REGEX, PROXY_CONFIG_SUB_NET_TEMPLATE, content
        )
        content = re.sub(SPARKLE_SIG_REGEX, SPARKLE_SIG_TEMPLATE, content)
        content = re.sub(SPARKLE_SE_REGEX, SPARKLE_SE_TEMPLATE, content)
        content = re.sub(TON_RATE_REGEX, TON_RATE_TEMPLATE, content)
        content = re.sub(CSRF_TOKEN_REGEX, CSRF_TOKEN_TEMPLATE, content)

        # there is a problem with the files with the same name (in the same path) but different case
        # the content is random because of the async
        # there is only one page with this problem, for now:
        # - corefork.telegram.org/constructor/Updates
        # - corefork.telegram.org/constructor/updates
        async with aiofiles.open(filename, "w", encoding="utf-8") as f:
            logger.info(f"Write to {filename}")
            await f.write(content)


async def _crawl_web(
    session: aiohttp.ClientSession, input_filename: str, output_folder=None
):
    with open(input_filename, "r") as f:
        tracked_urls = set([l.replace("\n", "") for l in f.readlines()])

    await asyncio.gather(*[crawl(url, session, output_folder) for url in tracked_urls])


async def crawl_web(session: aiohttp.ClientSession):
    await _crawl_web(session, INPUT_FILENAME, OUTPUT_SITES_FOLDER)


async def crawl_web_res(session: aiohttp.ClientSession):
    await _crawl_web(session, INPUT_RES_FILENAME, OUTPUT_RESOURCES_FOLDER)


async def start(mode: str):
    async with aiohttp.ClientSession(connector=CONNECTOR) as session:
        mode == "all" and await asyncio.gather(
            crawl_web(session),
            crawl_web_res(session),
        )
        mode == "web" and await asyncio.gather(
            crawl_web(session),
        )
        mode == "web_res" and await asyncio.gather(
            crawl_web_res(session),
        )


if __name__ == "__main__":
    run_mode = "all"
    if "MODE" in os.environ:
        run_mode = os.environ["MODE"]

    start_time = time()
    logger.info(f"Start crawling content of tracked urls...")
    asyncio.get_event_loop().run_until_complete(start(run_mode))
    logger.info(f"Stop crawling content in mode {run_mode}. {time() - start_time} sec.")
