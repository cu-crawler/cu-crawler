import asyncio
import logging
import os
import re
from asyncio import Queue
from asyncio.exceptions import TimeoutError
from collections import defaultdict
from functools import cache
from html import unescape
from time import time
from typing import Set
from urllib.parse import unquote

import aiohttp
from aiohttp import ClientConnectorError, ServerDisconnectedError


PROTOCOL = "https://"
URLS = {
    "centraluniversity.ru",
    "centraluniversity.ru/sitemap.xml",
    "education.tbank.ru",
    "education.tbank.ru/sitemap.xml",
    "algocourses.ru",
    "prodcontest.ru",
    # Notion and Yonote are not available without JavaScript
    # "centraluniversity.notion.site/622fecf82ea44f3281a54ac26ff41429",  # Хэндбук первокурсника
    # "centraluniversity.yonote.ru/share/01c6e64f-e9e2-418b-a481-8f8bcf1627a3",  # Хэндбук грантовика
    # "centraluniversity.yonote.ru/share/a405d5e3-2b75-4f60-8d8b-2a209e3465b8",  # Памятка участника буткемпа 5-9 февраля
}
ADDITIONAL_URLS = set()
BASE_URL_REGEX = r"(?:education.tbank|algocourses|centraluniversity|prodcontest).ru"

# disable crawling sub links for specific domains and url patterns
CRAWL_RULES = {
    # every rule is regex
    # empty string means match any url
    # allow rules with higher priority than deny
    "notion.site": {
        "deny": {
            "",
        },
    },
    "yonote.ru": {
        "deny": {
            "",
        },
    },
    "wiki.algocourses.ru": {
        "deny": {
            "",
        },
    },
    "ejudge.algocourses.ru": {
        "deny": {
            "",
        },
    },
    "static.centraluniversity.ru": {
        "deny": {
            r"\.pdf$",
        },
    },
    "algocourses.ru": {
        "deny": {
            r"\.pdf$",
        },
    },
}

DIRECT_LINK_REGEX = r"([-a-zA-Z0-9@:%._\+~#]{0,249}" + BASE_URL_REGEX + r")"
ABSOLUTE_LINK_REGEX = (
    r"([-a-zA-Z0-9@:%._\+~#]{0,248}"
    + BASE_URL_REGEX
    + r"\b[-a-zA-Z0-9@:%_\+.~#?&//=]*)"
)
RELATIVE_LINK_REGEX = r"\/(?!\/)([-a-zA-Z0-9\/@:%._\+~#]{0,249})"
RELATIVE_JS_SCRIPTS_REGEX = r'["\'](.*\.js)["\'\?]'

DOM_ATTRS = ["href", "src"]

OUTPUT_FILENAME = os.environ.get("OUTPUT_FILENAME", "tracked_links.txt")
OUTPUT_RESOURCES_FILENAME = os.environ.get(
    "OUTPUT_RESOURCES_FILENAME", "tracked_res_links.txt"
)

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
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
    "TE": "trailers",
}

logging.basicConfig(
    format="%(asctime)s  %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

VISITED_LINKS = set()
LINKS_TO_TRACK = set()
LINKS_TO_TRACKABLE_RESOURCES = set()

WORKERS_COUNT = 30
WORKERS_TASK_QUEUE = Queue()
URL_ATTEMPTS = defaultdict(int)


@cache
def should_exclude(url: str) -> bool:
    direct_link = re.findall(DIRECT_LINK_REGEX, url)[0]
    domain_rules = CRAWL_RULES.get(direct_link)
    if not domain_rules:
        return False

    allow_rules = domain_rules.get("allow", set())
    deny_rules = domain_rules.get("deny", set())

    exclude = False

    for regex in deny_rules:
        if re.search(regex, url):
            exclude = True
            break

    for regex in allow_rules:
        if re.search(regex, url):
            exclude = False
            break

    if exclude:
        logger.debug("Exclude %s by rules", url)

    return exclude


def find_absolute_links(html: str) -> Set[str]:
    absolute_links = set(re.findall(ABSOLUTE_LINK_REGEX, html))

    return {link for link in absolute_links if not should_exclude(link)}


def find_relative_links(html: str, cur_link: str) -> Set[str]:
    matches = re.findall(DIRECT_LINK_REGEX, cur_link)
    if not matches:
        return set()

    direct_cur_link = re.findall(DIRECT_LINK_REGEX, cur_link)[0]
    # optimization. when we want to exclude domain
    if should_exclude(cur_link):
        return set()

    relative_links = set()
    for attr in DOM_ATTRS:
        regex = f'{attr}="{RELATIVE_LINK_REGEX}'
        links = re.findall(regex, html)

        for link in links:
            url = f"{direct_cur_link}/{link}"
            if not should_exclude(url):
                relative_links.add(url)

    return relative_links


def find_relative_scripts(code: str, cur_link: str) -> Set[str]:
    matches = re.findall(DIRECT_LINK_REGEX, cur_link)
    if not matches:
        return set()

    direct_cur_link = re.findall(DIRECT_LINK_REGEX, cur_link)[0]

    relative_links = set()
    for link in re.findall(RELATIVE_JS_SCRIPTS_REGEX, code):
        # dirty magic for specific cases
        if "/" in link:  # path to file from the root
            url = f"{direct_cur_link}/{link}"
        else:  # it is a relative link from the current folder. not from the root
            current_folder_link, *_ = cur_link.rsplit("/", 1)
            url = f"{current_folder_link}/{link}"

        if not should_exclude(url):
            relative_links.add(url)

    return relative_links


def cleanup_links(links: Set[str]) -> Set[str]:
    cleaned_links = set()
    for tmp_link in links:
        # normalize link
        link = unquote(tmp_link)
        link = unescape(link)
        link = link.replace("www.", "")
        link = link.replace("http://", "").replace("https://", "")
        link = link.replace("//", "/")  # not a universal solution
        link = link.replace('"', "")  # regex fix hack

        # skip anchor links
        if "#" in link:
            continue

        # remove get params from link
        if "?" in link:
            link = "".join(link.split("?")[:-1])

        # skip mailto:
        link_parts = link.split(".")
        if "@" in link_parts[0]:
            continue

        # fix wildcard
        if link.startswith("."):
            link = link[1:]

        cleaned_links.add(link)

    return cleaned_links


def _is_x_content_type(content_types_set: Set[str], content_type) -> bool:
    for match_content_type in content_types_set:
        if match_content_type in content_type:
            return True

    return False


def is_textable_content_type(content_type: str) -> bool:
    textable_content_type = {
        "plain",
        "css",
        "json",
        "text",
        "javascript",
        "xml",
    }

    return _is_x_content_type(textable_content_type, content_type)


def is_trackable_content_type(content_type) -> bool:
    trackable_content_types = {
        "svg",
        "png",
        "jpeg",
        "x-icon",
        "gif",
        "mp4",
        "webm",
        "application/octet-stream",  # td updates
        "application/zip",
    }

    return _is_x_content_type(trackable_content_types, content_type)


class ServerSideError(Exception):
    pass


async def crawl_worker(session: aiohttp.ClientSession):
    while not WORKERS_TASK_QUEUE.empty():
        url = WORKERS_TASK_QUEUE.get_nowait()

        try:
            await _crawl(url, session)
        except (
            ServerSideError,
            ServerDisconnectedError,
            TimeoutError,
            ClientConnectorError,
        ) as e:
            URL_ATTEMPTS[url] += 1
            attempt = URL_ATTEMPTS[url]
            if attempt > 3:
                logger.warning(f"Url {url} failed after {attempt} attempts, ignoring")
                continue

            logger.warning(f"Client or timeout error: {e}. Retrying {url} (attempt #{attempt})")

            WORKERS_TASK_QUEUE.put_nowait(url)
            if url in VISITED_LINKS:
                VISITED_LINKS.remove(url)


async def _crawl(url: str, session: aiohttp.ClientSession):
    if url in VISITED_LINKS:
        return
    VISITED_LINKS.add(url)

    try:
        logger.debug("[%s] Process %s", len(VISITED_LINKS), url)
        async with session.get(
            f"{PROTOCOL}{url}", allow_redirects=True, timeout=TIMEOUT
        ) as response:
            content_type = response.headers.get("content-type")

            if 499 < response.status < 600:
                VISITED_LINKS.remove(url)
                logger.warning(f"Error 5XX. Retrying {url}")
                raise ServerSideError(f"{response.status} code")

            if response.status not in {200, 304}:
                if response.status != 302:
                    content = await response.text(encoding="UTF-8")
                    logger.warning(
                        f"Skip {url} because status code == {response.status}. Content: {content}"
                    )
                return

            if is_textable_content_type(content_type):
                # aiohttp will cache raw content. we don't worry about it
                raw_content = await response.read()
                content = await response.text(encoding="UTF-8")

                LINKS_TO_TRACK.add(url)
                logger.debug("Add %s to LINKS_TO_TRACK", url)

                absolute_links = cleanup_links(find_absolute_links(content))

                relative_links_finder = find_relative_links
                if "javascript" in content_type:
                    relative_links_finder = find_relative_scripts

                relative_links = cleanup_links(relative_links_finder(content, url))

                sub_links = absolute_links | relative_links
                for sub_url in sub_links:
                    if sub_url not in VISITED_LINKS:
                        WORKERS_TASK_QUEUE.put_nowait(sub_url)
            elif is_trackable_content_type(content_type):
                LINKS_TO_TRACKABLE_RESOURCES.add(url)
                logger.debug("Add %s to LINKS_TO_TRACKABLE_RESOURCES", url)
            else:
                logger.warning(f"Unhandled type: {content_type} from {url}")

            # telegram url can work with and without a trailing slash (no redirect).
            # note: not on every subdomain ;d
            # so this is a problem when we have random behavior with a link will be added
            # this if resolve this issue.
            # if available both links, we prefer without a trailing slash
            for links_set in (LINKS_TO_TRACK, LINKS_TO_TRACKABLE_RESOURCES):
                without_trailing_slash = url[:-1:] if url.endswith("/") else url
                if (
                    without_trailing_slash in links_set
                    and f"{without_trailing_slash}/" in links_set
                ):
                    links_set.remove(f"{without_trailing_slash}/")
                    logger.debug("Remove %s/", without_trailing_slash)
    except UnicodeDecodeError:
        logger.warning(
            f"Codec can't decode bytes. So it was a tgs file or response with broken content type {url}"
        )

        if raw_content.startswith(b"GIF"):
            LINKS_TO_TRACKABLE_RESOURCES.add(url)
            logger.debug("Add %s to LINKS_TO_TRACKABLE_RESOURCES (raw content)", url)


async def start(url_list: Set[str]):
    for url in url_list:
        WORKERS_TASK_QUEUE.put_nowait(url)

    async with aiohttp.ClientSession(connector=CONNECTOR, headers=HEADERS) as session:
        await asyncio.gather(*[crawl_worker(session) for _ in range(WORKERS_COUNT)])


if __name__ == "__main__":
    LINKS_TO_TRACK = LINKS_TO_TRACK | ADDITIONAL_URLS

    logger.info("Start crawling links...")
    start_time = time()
    asyncio.get_event_loop().run_until_complete(start(URLS))
    logger.info(f"Stop crawling links. {time() - start_time} sec.")

    try:
        OLD_URL_LIST = set()
        for filename in (OUTPUT_FILENAME, OUTPUT_RESOURCES_FILENAME):
            with open(filename, "r") as f:
                OLD_URL_LIST |= set([l.replace("\n", "") for l in f.readlines()])

        CURRENT_URL_LIST = LINKS_TO_TRACK | LINKS_TO_TRACKABLE_RESOURCES

        logger.info(f"Is equal: {OLD_URL_LIST == CURRENT_URL_LIST}")
        logger.info(
            f"Deleted ({len(OLD_URL_LIST - CURRENT_URL_LIST)}): {OLD_URL_LIST - CURRENT_URL_LIST}"
        )
        logger.info(
            f"Added ({len(CURRENT_URL_LIST - OLD_URL_LIST)}): {CURRENT_URL_LIST - OLD_URL_LIST}"
        )
    except IOError:
        pass

    with open(OUTPUT_FILENAME, "w") as f:
        f.write("\n".join(sorted(LINKS_TO_TRACK)))

    with open(OUTPUT_RESOURCES_FILENAME, "w") as f:
        f.write("\n".join(sorted(LINKS_TO_TRACKABLE_RESOURCES)))
