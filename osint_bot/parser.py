from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import unquote, urlsplit


class QueryError(ValueError):
    pass


@dataclass(frozen=True)
class Query:
    kind: str
    value: str
    platform: str = ""


SOCIAL_HOSTS = {
    "vk.com": "vk", "vkontakte.ru": "vk", "tiktok.com": "tiktok",
    "instagram.com": "instagram", "ok.ru": "ok", "t.me": "telegram",
    "telegram.me": "telegram", "github.com": "github",
}
DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
VIN = re.compile(r"[A-HJ-NPR-Z0-9]{17}\Z")
PLATE = re.compile(r"[АВЕКМНОРСТУХABEKMHOPCTYX]\d{3}[АВЕКМНОРСТУХABEKMHOPCTYX]{2}\d{2,3}\Z", re.I)


def normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    try:
        domain = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise QueryError("Некорректное доменное имя.") from None
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(not DOMAIN_LABEL.fullmatch(x) for x in labels):
        raise QueryError("Отправьте домен, например example.com.")
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", labels[-1]):
        raise QueryError("Некорректная доменная зона.")
    if labels[-1] in {"local", "localhost", "internal", "lan", "home", "onion", "invalid", "test"}:
        raise QueryError("Локальные и специальные домены не поддерживаются.")
    return domain


def ip_query(value: str) -> Query:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise QueryError("Некорректный IP-адрес.") from None
    if not address.is_global or "%" in value:
        raise QueryError("Поддерживаются только публичные IP-адреса.")
    return Query("ip", str(address))


def username(value: str) -> str:
    value = value.lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", value):
        raise QueryError("Логин должен содержать латинские буквы, цифры, _, . или -.")
    return value


def parse_query(text: str) -> Query:
    text = text.strip()
    if not text or len(text) > 512 or any(ord(c) < 32 for c in text):
        raise QueryError("Отправьте один запрос длиной до 512 символов.")
    if text.startswith("/"):
        command, _, argument = text.partition(" ")
        command = command.split("@", 1)[0].lower()
        argument = argument.strip()
        if command in {"/start", "/help", "/privacy", "/sources", "/id", "/menu"}:
            return Query(command[1:], "")
        if not argument:
            raise QueryError("После команды нужно указать значение. Примеры: /help")
        if command in {"/passport", "/snils", "/vu", "/tag", "/adr", "/person"}:
            return Query("restricted", command)
        if command in {"/inn", "/ogrn"}:
            expected = {"/inn": (10, 12), "/ogrn": (13, 15)}[command]
            if not argument.isascii() or not argument.isdigit() or len(argument) not in expected:
                raise QueryError("Проверьте количество цифр в ИНН или ОГРН.")
            return Query(command[1:], argument)
        if command == "/user":
            return Query("username", username(argument))
        if command == "/vin":
            if not VIN.fullmatch(argument.upper()):
                raise QueryError("VIN должен содержать 17 символов, без I, O и Q.")
            return Query("vin", argument.upper())
        if command == "/ip":
            return ip_query(argument)
        if command == "/domain":
            return Query("domain", normalize_domain(argument))
        if command == "/phone":
            if not re.fullmatch(r"[+\d() -]+", argument) or not 7 <= len(re.sub(r"\D", "", argument)) <= 15:
                raise QueryError("Проверьте формат телефона.")
            return Query("phone", argument)
        if command == "/email":
            query = parse_query(argument)
            if query.kind != command[1:]:
                raise QueryError("Проверьте формат телефона или email.")
            return query
        raise QueryError("Неизвестная команда. Доступные команды: /help")

    if re.fullmatch(r"tg[1-9]\d{0,19}", text, re.I):
        return Query("telegram_id", text[2:])
    if text.startswith("@"):
        return Query("username", username(text))
    if "@" in text and "/" not in text and "://" not in text:
        local, separator, domain = text.rpartition("@")
        if not separator or len(local) > 64 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
            raise QueryError("Некорректный email. Пример: name@example.com")
        if local.startswith(".") or local.endswith(".") or ".." in local:
            raise QueryError("Некорректная локальная часть email.")
        return Query("email", local + "@" + normalize_domain(domain))
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return ip_query(text)
    if re.fullmatch(r"\d+(?:\.\d+){3}", text) or ":" in text and not "/" in text and not re.fullmatch(r"\d{2}:\d{2}:\d{6,7}:\d+", text):
        raise QueryError("Некорректный IP-адрес.")
    if re.fullmatch(r"\d{2}:\d{2}:\d{6,7}:\d+", text):
        return Query("cadastre", text)
    if VIN.fullmatch(text.upper()):
        return Query("vin", text.upper())
    if PLATE.fullmatch(text.replace(" ", "")):
        return Query("plate", text.replace(" ", "").upper())
    if re.fullmatch(r"\d{13}|\d{15}", text):
        return Query("ogrn", text)
    if re.fullmatch(r"[+\d() -]+", text):
        digits = re.sub(r"\D", "", text)
        if 7 <= len(digits) <= 15:
            return Query("phone", text)
        raise QueryError("Проверьте формат номера; ИНН вводится через /inn.")
    if text.startswith(("http://", "https://")) or "." in text and not " " in text:
        try:
            parsed = urlsplit(text if "://" in text else "https://" + text)
            if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.port not in {None, 80, 443}:
                raise ValueError
            host = (parsed.hostname or "").lower()
        except ValueError:
            raise QueryError("Некорректная ссылка.") from None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return ip_query(host)
        social_host = host.removeprefix("www.").removeprefix("m.")
        if social_host in SOCIAL_HOSTS:
            path = unquote(parsed.path).strip("/")
            platform = SOCIAL_HOSTS[social_host]
            if platform == "ok" and re.fullmatch(r"profile/\d+", path):
                return Query("social", path, platform)
            if platform == "telegram" and (path.startswith("+") or path.startswith(("joinchat/", "c/"))):
                raise QueryError("Нужна ссылка на публичный профиль или канал.")
            if "/" in path or not path:
                raise QueryError("Отправьте ссылку на сам профиль, без ссылки на публикацию.")
            return Query("social", username(path), platform)
        return Query("domain", normalize_domain(host))
    if re.fullmatch(r"[А-Яа-яЁёA-Za-z -]+(?:\s+\d[\d. -]*)?", text) and " " in text:
        return Query("restricted", "person")
    raise QueryError("Не удалось определить запрос. Отправьте домен, IP, @логин, email, телефон или /vin. Примеры: /help")
