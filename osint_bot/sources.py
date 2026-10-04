"""Only fixed API endpoints and RDAP services from the IANA bootstrap registry."""
import asyncio
import ipaddress
import json
import re
import time
from html import unescape
from urllib.parse import quote, urljoin, urlsplit

import httpx

from .parser import QueryError, normalize_domain


class SourceError(Exception):
    """A user-readable error which contains neither a token nor query data."""


FIXED_HOSTS = {"dns.google", "data.iana.org", "api.github.com",
               "vpic.nhtsa.dot.gov", "suggestions.dadata.ru", "api.search.brave.com"}


def validate_source_url(url: str, allowed_hosts: set[str]) -> None:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in {None, 443}:
            raise ValueError
        if host not in allowed_hosts or parsed.fragment:
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise ValueError
    except ValueError:
        raise SourceError("Источник вернул неподдерживаемый адрес.") from None


class SourceClient:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        self._bootstrap_cache: dict[str, tuple[float, dict]] = {}

    async def _json(self, url: str, *, params=None, body=None, headers=None,
                    allowed_hosts=None, redirects=False) -> tuple[dict, str]:
        hosts = FIXED_HOSTS | (allowed_hosts or set())
        for _ in range(5):
            validate_source_url(url, hosts)
            try:
                async with self.client.stream("POST" if body is not None else "GET", url,
                                              params=params, json=body, headers=headers,
                                              follow_redirects=False) as response:
                    if response.status_code in {301, 302, 303, 307, 308} and redirects:
                        location = response.headers.get("location")
                        if not location:
                            raise SourceError("Источник вернул пустое перенаправление.")
                        url = urljoin(str(response.url), location)
                        params = None
                        continue
                    if response.status_code == 404:
                        raise SourceError("В этом источнике запись не найдена.")
                    if response.status_code in {401, 403}:
                        raise SourceError("Источник ограничил доступ: проверьте ключ или квоту API.")
                    if response.status_code == 429:
                        raise SourceError("Лимит источника исчерпан. Повторите позже.")
                    if not 200 <= response.status_code < 300:
                        raise SourceError("Источник сейчас недоступен.")
                    buffer = bytearray()
                    async for chunk in response.aiter_bytes():
                        buffer.extend(chunk)
                        if len(buffer) > 2_000_000:
                            raise SourceError("Ответ источника превышает допустимый размер.")
                    data = json.loads(buffer)
                    if not isinstance(data, dict):
                        raise SourceError("Источник вернул неожиданный формат ответа.")
                    return data, str(response.url)
            except (httpx.HTTPError, asyncio.TimeoutError):
                raise SourceError("Не удалось связаться с источником. Повторите позже.") from None
            except (ValueError, UnicodeError):
                raise SourceError("Источник вернул некорректный JSON.") from None
        raise SourceError("Слишком много перенаправлений источника.")

    async def dns(self, domain: str, kind: str) -> tuple[list[str], str]:
        data, url = await self._json("https://dns.google/resolve", params={
            "name": domain, "type": kind, "edns_client_subnet": "0.0.0.0/0"})
        if data.get("Status") == 3:
            return ["Домен не найден в DNS (NXDOMAIN)."], url
        if data.get("Status") != 0:
            raise SourceError("DNS-сервис не смог выполнить запрос.")
        expected_type = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "PTR": 12}[kind]
        records = [str(x["data"]) for x in data.get("Answer", [])
                   if isinstance(x, dict) and x.get("type") == expected_type and "data" in x]
        return records[:8] or ["Записи этого типа отсутствуют."], url

    async def _bootstrap(self, name: str) -> dict:
        cached = self._bootstrap_cache.get(name)
        if cached and time.monotonic() - cached[0] < 3600:
            return cached[1]
        data, _ = await self._json(f"https://data.iana.org/rdap/{name}.json")
        if not isinstance(data.get("services"), list):
            raise SourceError("Некорректный реестр RDAP.")
        self._bootstrap_cache[name] = (time.monotonic(), data)
        return data

    async def rdap(self, value: str, kind: str) -> tuple[dict, str]:
        address = ipaddress.ip_address(value) if kind == "ip" else None
        filename = ("ipv4" if address.version == 4 else "ipv6") if address else "dns"
        bootstrap = await self._bootstrap(filename)
        hosts: set[str] = set()
        matches: list[tuple[int, str]] = []
        for service in bootstrap["services"]:
            if not isinstance(service, list) or len(service) != 2:
                continue
            keys, urls = service
            valid_urls = []
            for url in urls:
                try:
                    host = urlsplit(url).hostname
                    validate_source_url(url, {host})
                except (SourceError, ValueError, TypeError):
                    continue
                hosts.add(host)
                valid_urls.append(url)
            for key in keys:
                if address:
                    try:
                        network = ipaddress.ip_network(key)
                    except ValueError:
                        continue
                    score = network.prefixlen if address in network else -1
                else:
                    score = len(key) if value == key or value.endswith("." + key) else -1
                if score >= 0:
                    matches.extend((score, url) for url in valid_urls)
        if not matches:
            raise SourceError("Для этой зоны или сети не найден HTTPS-сервис RDAP в реестре IANA.")
        endpoint = max(matches, key=lambda item: item[0])[1].rstrip("/")
        return await self._json(endpoint + f"/{'ip' if address else 'domain'}/{quote(value, safe='')}",
                                allowed_hosts=hosts, redirects=True,
                                headers={"Accept": "application/rdap+json, application/json"})

    async def github(self, handle: str, token: str = "") -> tuple[dict, str]:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", handle) or "--" in handle:
            raise SourceError("Этот логин не соответствует формату GitHub.")
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        return await self._json(f"https://api.github.com/users/{quote(handle, safe='')}", headers=headers)

    async def brave_search(self, terms: str, token: str) -> list[tuple[str, str]]:
        if not token:
            raise SourceError("Для поиска нужен BRAVE_SEARCH_API_KEY.")
        data, _ = await self._json("https://api.search.brave.com/res/v1/web/search",
                                  params={"q": terms, "count": 5, "result_filter": "web",
                                          "spellcheck": "false", "text_decorations": "false",
                                          "safesearch": "strict"},
                                  headers={"Accept": "application/json", "X-Subscription-Token": token})
        web = data.get("web")
        if web is None:
            return []
        if not isinstance(web, dict) or not isinstance(web.get("results"), list):
            raise SourceError("Brave вернул неожиданный формат результатов.")
        results = []
        seen = set()
        for record in web["results"]:
            if not isinstance(record, dict):
                continue
            url = record.get("url")
            if not isinstance(url, str) or len(url) > 2048 or any(c.isspace() or ord(c) < 32 for c in url):
                continue
            try:
                parsed = urlsplit(url)
                host = parsed.hostname or ""
                validate_source_url(url, {host})
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    normalize_domain(host)
            except (SourceError, QueryError, ValueError):
                continue
            if url in seen:
                continue
            seen.add(url)
            title = record.get("title")
            title = unescape(re.sub(r"<[^>]*>", "", title)) if isinstance(title, str) else host
            title = " ".join(title.split())[:200] or host
            results.append((title, url))
            if len(results) == 5:
                break
        return results

    async def vin(self, vin: str) -> tuple[dict, str]:
        data, url = await self._json(f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{vin}",
                                     params={"format": "json"})
        records = data.get("Results")
        if not isinstance(records, list) or not records or not isinstance(records[0], dict):
            raise SourceError("NHTSA не вернул данные для VIN.")
        return records[0], url

    async def company(self, identifier: str, token: str) -> tuple[dict, str]:
        data, url = await self._json("https://suggestions.dadata.ru/suggestions/api/4_1/rs/findById/party",
                                     body={"query": identifier, "type": "LEGAL", "count": 1},
                                     headers={"Authorization": "Token " + token})
        records = data.get("suggestions")
        if not isinstance(records, list) or not records:
            raise SourceError("Юридическое лицо в DaData не найдено.")
        record = records[0].get("data", {})
        if record.get("type") != "LEGAL":
            raise SourceError("Источник не вернул карточку юридического лица.")
        return record, url
