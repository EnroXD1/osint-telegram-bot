import asyncio
import ipaddress
import re

import phonenumbers
from phonenumbers import carrier, geocoder

from .config import Config
from .parser import Query
from .reports import Card
from .sources import SourceClient, SourceError


PROFILE_TEMPLATES = {
    "telegram": ("Telegram", "https://t.me/{}"),
    "vk": ("ВКонтакте", "https://vk.com/{}"),
    "tiktok": ("TikTok", "https://www.tiktok.com/@{}"),
    "instagram": ("Instagram", "https://www.instagram.com/{}/"),
    "ok": ("Одноклассники", "https://ok.ru/{}"),
    "github": ("GitHub", "https://github.com/{}"),
}


def valid_inn(value: str) -> bool:
    digits = [int(x) for x in value]
    if not any(digits):
        return False
    def checksum(weights):
        return sum(a * b for a, b in zip(digits, weights)) % 11 % 10
    if len(digits) == 10:
        return checksum([2, 4, 10, 3, 5, 9, 4, 6, 8]) == digits[9]
    if len(digits) == 12:
        return checksum([7, 2, 4, 10, 3, 5, 9, 4, 6, 8]) == digits[10] and checksum([3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]) == digits[11]
    return False


def valid_ogrn(value: str) -> bool:
    if not any(int(x) for x in value) or len(value) not in {13, 15}:
        return False
    divisor = 11 if len(value) == 13 else 13
    return int(value[:-1]) % divisor % 10 == int(value[-1])


class LookupService:
    def __init__(self, sources: SourceClient, config: Config):
        self.sources = sources
        self.config = config

    async def lookup(self, query: Query, bot=None) -> list[Card]:
        method = getattr(self, "_" + query.kind, None)
        if method is None:
            return [Card("Запрос не поддерживается", ["Доступные запросы: /help"])]
        return await method(query, bot)

    async def _domain(self, query, bot):
        tasks = [self.sources.dns(query.value, kind) for kind in ("A", "AAAA", "MX", "NS")]
        results = await asyncio.gather(*tasks, self.sources.rdap(query.value, "domain"), return_exceptions=True)
        lines = ["Домен: " + query.value]
        for kind, result in zip(("A", "AAAA", "MX", "NS"), results[:4]):
            if isinstance(result, SourceError):
                lines.append(f"{kind}: {result}")
            elif isinstance(result, Exception):
                raise result
            else:
                lines.extend(f"{kind}: {value}" for value in result[0])
        cards = [Card("🌐 DNS", lines, [("Google Public DNS", "https://dns.google/resolve?name=" + query.value)])]
        result = results[-1]
        if isinstance(result, SourceError):
            cards.append(Card("Регистрация домена (RDAP)", [str(result), "RDAP для поддомена может отсутствовать; отправьте основной домен."], [("Реестр IANA", "https://data.iana.org/rdap/dns.json")]))
        elif isinstance(result, Exception):
            raise result
        else:
            data, url = result
            details = ["Имя: " + str(data.get("ldhName", query.value)),
                       "Статус: " + ", ".join(str(x) for x in data.get("status", [])[:8])]
            for event in data.get("events", [])[:8]:
                if isinstance(event, dict):
                    details.append(f"{event.get('eventAction', 'Событие')}: {event.get('eventDate', '—')}")
            for ns in data.get("nameservers", [])[:6]:
                details.append("NS: " + str(ns.get("ldhName", "—")))
            details.append("Персональные контакты владельца из RDAP не выводятся.")
            cards.append(Card("Регистрация домена (RDAP)", details, [("Ответ RDAP", url)]))
        return cards

    async def _ip(self, query, bot):
        data, url = await self.sources.rdap(query.value, "ip")
        details = ["IP: " + query.value]
        for key, label in (("name", "Сеть"), ("handle", "Идентификатор"), ("startAddress", "Начало диапазона"),
                           ("endAddress", "Конец диапазона"), ("country", "Страна регистрации сети"), ("type", "Тип")):
            if data.get(key):
                details.append(f"{label}: {data[key]}")
        details.append("Страна регистрации сети не определяет местоположение пользователя IP.")
        cards = [Card("🌐 IP / RDAP", details, [("Ответ RDAP", url)])]
        try:
            ptr, ptr_url = await self.sources.dns(ipaddress.ip_address(query.value).reverse_pointer, "PTR")
            cards.append(Card("Обратная DNS-запись", ptr, [("Ответ DNS", ptr_url)]))
        except SourceError as error:
            cards.append(Card("Обратная DNS-запись", [str(error)]))
        return cards

    async def _email(self, query, bot):
        domain = query.value.rsplit("@", 1)[1]
        records, url = await self.sources.dns(domain, "MX")
        null_mx = ["Null MX: домен заявляет, что не принимает электронную почту."] if "0 ." in records else []
        return [Card("📧 Email: домен и MX", ["Синтаксис соответствует поддерживаемому формату.", "Домен: " + domain,
                    *["MX: " + x for x in records], "MX показывает почтовую инфраструктуру домена. Это не проверка существования ящика или его владельца.",
                    *null_mx, "Во внешний сервис отправлен только домен email."], [("Ответ DNS", url)])]

    async def _phone(self, query, bot):
        raw = query.value
        digits = re.sub(r"\D", "", raw)
        if not raw.startswith("+") and len(digits) == 11 and digits.startswith("7"):
            raw = "+" + digits
        try:
            number = phonenumbers.parse(raw, self.config.phone_region)
        except phonenumbers.NumberParseException:
            return [Card("📲 Телефон", ["Не удалось разобрать номер. Используйте международный формат с +."])]
        return [Card("📲 Телефон: план нумерации", [
            "Формат: " + phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "Допустимая длина: " + ("да" if phonenumbers.is_possible_number(number) else "нет"),
            "Соответствует плану нумерации: " + ("да" if phonenumbers.is_valid_number(number) else "нет"),
            "Код региона плана нумерации: " + (phonenumbers.region_code_for_number(number) or "нет данных"),
            "Описание диапазона: " + (geocoder.description_for_number(number, "ru") or "нет данных"),
            "Оператор из справочника диапазонов: " + (carrier.name_for_number(number, "ru") or "нет данных"),
            "Это не проверка активности SIM, владельца или текущего местоположения. Оператор мог измениться после переноса номера.",
            "Номер проверен локально и не отправлялся сторонним сервисам."],
            [("Источник справочника: python-phonenumbers", "https://github.com/daviddrysdale/python-phonenumbers")])]

    async def _vin(self, query, bot):
        data, url = await self.sources.vin(query.value)
        lines = ["VIN: " + query.value]
        for key, label in (("Make", "Марка"), ("Model", "Модель"), ("ModelYear", "Модельный год"),
                           ("VehicleType", "Тип"), ("BodyClass", "Кузов"), ("FuelTypePrimary", "Топливо"),
                           ("DisplacementL", "Объём двигателя, л"), ("PlantCountry", "Страна сборки")):
            if data.get(key):
                lines.append(f"{label}: {data[key]}")
        lines.append("Код результата NHTSA: " + str(data.get("ErrorCode", "не указан")))
        if data.get("ErrorText"):
            lines.append("Комментарий NHTSA: " + str(data["ErrorText"]))
        lines.append("Полнота зависит от покрытия NHTSA. Сведения о владельцах, пробеге, ДТП и регистрации не запрашиваются.")
        return [Card("🚘 Расшифровка VIN", lines, [("Ответ NHTSA vPIC", url)])]

    async def _github_card(self, handle):
        try:
            data, url = await self.sources.github(handle, self.config.github_token)
        except SourceError as error:
            return Card("GitHub", [str(error), "API не подтвердил профиль; ссылка ниже не проверена.",
                                   "При исчерпании общей квоты можно подключить GITHUB_API_TOKEN."],
                        [("Открыть ссылку для проверки", "https://github.com/" + handle)])
        lines = ["Публичный профиль найден на GitHub.", "Логин: " + str(data.get("login", handle)),
                 "Имя в профиле: " + str(data.get("name") or "не указано"),
                 "Описание: " + str(data.get("bio") or "не указано"),
                 "Публичные репозитории: " + str(data.get("public_repos", 0)),
                 "Создан: " + str(data.get("created_at", "—")),
                 "Одинаковый логин на разных платформах не доказывает, что аккаунты принадлежат одному человеку."]
        return Card("💬 GitHub: открытый профиль", lines, [("Профиль", "https://github.com/" + handle), ("Ответ API", url)])

    async def _telegram_card(self, handle, bot):
        card = Card("📟 Telegram: публичная карточка", ["Логин: @" + handle],
                    [("Открыть в Telegram", "https://t.me/" + handle),
                     ("Источник: Telegram Bot API", "https://core.telegram.org/bots/api#getchat")])
        if bot is None or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", handle):
            card.lines.append("Ссылка сформирована; существование аккаунта не проверено.")
            return card
        from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError, TelegramAPIError
        try:
            chat = await bot.get_chat("@" + handle)
            if chat.type not in {"channel", "supergroup"} or getattr(chat, "is_direct_messages", False):
                card.lines.append("Публичный канал или группа не подтверждены. Личный профиль по произвольному @логину через Bot API не ищется.")
                return card
            card.lines = ["💬 ID канала/группы: " + str(chat.id),
                          "🔗 Логин: @" + (chat.username or handle),
                          "📝 Название: " + (chat.title or "не указано"),
                          "🏷 Тип: " + ("публичный канал" if chat.type == "channel" else "публичная группа"),
                          "📄 Описание: " + (chat.description or "не указано"),
                          "✅ Сведения получены через Telegram Bot API."]
        except (TelegramBadRequest, TelegramForbiddenError):
            card.lines.append("Публичный канал или группа через Bot API не подтверждены. Это не означает, что аккаунт отсутствует. Личный профиль по произвольному @логину через Bot API не ищется.")
        except TelegramAPIError:
            card.lines.append("Telegram API сейчас недоступен; ссылка не проверена.")
        return card

    async def _username(self, query, bot):
        github, telegram = await asyncio.gather(self._github_card(query.value), self._telegram_card(query.value, bot))
        links = [(name, template.format(query.value)) for key, (name, template) in PROFILE_TEMPLATES.items()
                 if key not in {"telegram", "github"}]
        return [github, telegram, Card("Другие платформы: ссылки для проверки", [
            "Существование профилей по этим ссылкам не проверено.",
            "Совпадение логина не подтверждает личность владельца."], links)]

    async def _social(self, query, bot):
        if query.platform == "github":
            return [await self._github_card(query.value)]
        if query.platform == "telegram":
            return [await self._telegram_card(query.value, bot)]
        name, template = PROFILE_TEMPLATES[query.platform]
        return [Card("💬 " + name, ["Публичная ссылка распознана.", "Существование и содержимое профиля не проверены: API этой платформы не подключён."],
                     [("Открыть профиль", template.format(query.value))])]

    async def _inn(self, query, bot):
        return await self._business(query, valid_inn(query.value), len(query.value) == 10)

    async def _ogrn(self, query, bot):
        return await self._business(query, valid_ogrn(query.value), len(query.value) == 13)

    async def _business(self, query, valid, legal):
        title = "🏢 " + query.kind.upper()
        lines = ["Контрольные цифры: " + ("корректны" if valid else "не совпадают"),
                 "Контрольная цифра не подтверждает наличие записи в реестре."]
        if not legal:
            lines.append("Идентификатор физлица или ИП: выполняется только локальная проверка формата. Поиск сведений о человеке не запускается.")
            return [Card(title, lines)]
        lines.append("Идентификатор: " + query.value)
        card = Card(title, lines, [("Проверить в ЕГРЮЛ (введите идентификатор)", "https://egrul.nalog.ru/index.html")])
        if not valid:
            return [card]
        if not self.config.dadata_token:
            card.lines.append("Автоматическая карточка организации доступна после подключения ключа DaData; сейчас доступна ссылка на официальный реестр.")
            return [card]
        try:
            data, _ = await self.sources.company(query.value, self.config.dadata_token)
        except SourceError as error:
            card.lines.append(str(error))
            return [card]
        name = data.get("name") or {}
        card.lines.append("Название: " + str(name.get("short_with_opf") or name.get("full_with_opf") or "—"))
        for key, label in (("inn", "ИНН"), ("kpp", "КПП"), ("ogrn", "ОГРН"), ("okved", "ОКВЭД")):
            card.lines.append(f"{label}: {data.get(key) or '—'}")
        state = data.get("state") or {}
        card.lines.append("Статус DaData: " + str(state.get("status", "—")))
        card.links.append(("Источник: DaData / ЕГРЮЛ", "https://dadata.ru/api/find-party/"))
        return [card]

    async def _telegram_id(self, query, bot):
        return [Card("📟 Telegram ID", ["ID распознан.", "ID пользователя не позволяет найти произвольный личный профиль через Bot API. Отправьте публичный @логин или t.me-ссылку."])]

    async def _plate(self, query, bot):
        return [Card("🚘 Госномер", ["Госномер распознан.", "Источник сведений о транспортном средстве по номеру не подключён. Для технических характеристик отправьте VIN. Владельца по номеру бот не ищет."])]

    async def _cadastre(self, query, bot):
        return [Card("🏚 Кадастровый номер", ["Формат кадастрового номера распознан.", "Автоматический источник сведений об объекте не подключён. Поиск собственников не выполняется."])]

    async def _restricted(self, query, bot):
        return [Card("Доступные возможности", ["Поиск частных лиц по ФИО, дате рождения, документам, адресам и телефонным книгам здесь не выполняется.",
                     "Можно проверить домен, IP, VIN, реквизиты компании или публичный профиль. Примеры: /help"])]
