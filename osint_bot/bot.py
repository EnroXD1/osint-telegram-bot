import asyncio
from collections import OrderedDict, deque
import logging
import time

import httpx
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.exceptions import TelegramAPIError
from aiogram.types import BotCommand, KeyboardButton, Message, ReplyKeyboardMarkup

from .config import Config
from .parser import QueryError, parse_query
from .service import LookupService
from .sources import SourceClient, SourceError
from .texts import HELP, PHOTO_REPLY, PRIVACY, SOURCES


logger = logging.getLogger("osint_bot")


class RateLimiter:
    def __init__(self, limit: int, max_users: int = 10_000):
        self.limit = limit
        self.max_users = max_users
        self.users = OrderedDict()

    def check(self, user_id: int, now: float | None = None) -> tuple[bool, bool]:
        now = time.monotonic() if now is None else now
        entries, notified = self.users.pop(user_id, (deque(), False))
        while entries and now - entries[0] >= 60:
            entries.popleft()
        if len(entries) < self.limit:
            entries.append(now)
            self.users[user_id] = (entries, False)
            result = (True, False)
        else:
            self.users[user_id] = (entries, True)
            result = (False, not notified)
        while len(self.users) > self.max_users:
            self.users.popitem(last=False)
        return result


KEYBOARD = ReplyKeyboardMarkup(keyboard=[
    [KeyboardButton(text="🌐 Домен / IP"), KeyboardButton(text="💬 Профили")],
    [KeyboardButton(text="📲 Телефон / email"), KeyboardButton(text="🚘 VIN")],
    [KeyboardButton(text="🏢 Компания"), KeyboardButton(text="ℹ️ Помощь")],
], resize_keyboard=True, input_field_placeholder="Домен, IP, @логин или /vin …")

HINTS = {
    "🌐 Домен / IP": "Отправьте example.com или 1.1.1.1. Можно использовать /domain и /ip.",
    "💬 Профили": "Отправьте @octocat, /user octocat или публичную ссылку на профиль.",
    "📲 Телефон / email": "Отправьте /phone +79999688666 или name@example.com. Бот проверяет формат и общие технические сведения.",
    "🚘 VIN": "Отправьте /vin 1HGCM82633A004352. Бот запрашивает технические характеристики в NHTSA.",
    "🏢 Компания": "Отправьте /inn 7707083893 или /ogrn 1027700132195. Карточка юрлица появляется при подключении DaData.",
    "ℹ️ Помощь": HELP,
}


def build_router(config: Config, service: LookupService) -> Router:
    router = Router(name="public_sources")
    router.message.filter(F.chat.type == "private")
    limiter = RateLimiter(config.rate_limit)
    active_users: set[int] = set()

    @router.message()
    async def handle(message: Message, bot: Bot):
        if not message.from_user:
            return
        user_id = message.from_user.id
        allowed, notify = limiter.check(user_id)
        if not allowed:
            if notify:
                await message.answer("Слишком много запросов. Подождите примерно минуту.")
            return
        if config.allowed_user_ids and user_id not in config.allowed_user_ids:
            await message.answer("Доступ к этому боту ограничен владельцем.")
            return
        if message.photo:
            await message.answer(PHOTO_REPLY)
            return
        if not message.text:
            await message.answer("Поддерживаются текстовые запросы. Примеры: /help")
            return
        if message.text in HINTS:
            await message.answer(HINTS[message.text], reply_markup=KEYBOARD)
            return
        try:
            query = parse_query(message.text)
        except QueryError as error:
            await message.answer(str(error), parse_mode=None)
            return
        if query.kind in {"start", "help", "menu", "privacy", "sources", "id"}:
            text = {"privacy": PRIVACY, "sources": SOURCES, "id": f"Ваш Telegram ID: <code>{user_id}</code>"}.get(query.kind, HELP)
            await message.answer(text, reply_markup=KEYBOARD)
            return
        if user_id in active_users:
            await message.answer("Ваш предыдущий запрос ещё выполняется.")
            return
        active_users.add(user_id)
        try:
            await bot.send_chat_action(message.chat.id, "typing")
            try:
                cards = await asyncio.wait_for(service.lookup(query, bot), timeout=25)
            except SourceError as error:
                await message.answer(str(error), parse_mode=None)
                return
            except asyncio.TimeoutError:
                await message.answer("Источник отвечает слишком долго. Повторите запрос позже.")
                return
            except TelegramAPIError:
                raise
            except Exception as error:
                # Log only the exception class, never the request or credentials.
                logger.warning("Lookup failed: %s", type(error).__name__)
                await message.answer("Не удалось обработать ответ источника. Повторите позже.")
                return
            for card in cards:
                await message.answer(card.render())
        finally:
            active_users.discard(user_id)

    @router.errors()
    async def handle_error(event):
        logger.warning("Telegram event failed: %s", type(event.exception).__name__)
        return True

    return router


async def run_bot(config: Config) -> None:
    bot = Bot(config.token, default=DefaultBotProperties(parse_mode="HTML", link_preview_is_disabled=True))
    try:
        info = await bot.get_me()
        webhook = await bot.get_webhook_info()
        if webhook.url:
            raise ValueError("У бота уже настроен webhook. Используйте отдельного бота для этой версии с polling.")
        async with httpx.AsyncClient(timeout=config.timeout, trust_env=False,
                                     limits=httpx.Limits(max_connections=24, max_keepalive_connections=12),
                                     headers={"User-Agent": "OpenTraceTelegramBot/1.0"}) as client:
            service = LookupService(SourceClient(client), config)
            dispatcher = Dispatcher()
            dispatcher.include_router(build_router(config, service))
            await bot.set_my_commands([BotCommand(command=command, description=description) for command, description in [
                ("start", "Главное меню"), ("help", "Примеры запросов"), ("sources", "Источники и ограничения"),
                ("privacy", "Обработка данных"), ("id", "Мой Telegram ID"),
                ("domain", "Проверить домен"), ("ip", "Проверить IP"), ("vin", "Расшифровать VIN"),
                ("phone", "Проверить формат телефона"), ("email", "Проверить почтовый домен"),
                ("user", "Проверить публичный логин"), ("inn", "Проверить ИНН"), ("ogrn", "Проверить ОГРН")]])
            print(f"Бот @{info.username} запущен. Для остановки нажмите Ctrl+C.", flush=True)
            await dispatcher.start_polling(bot, allowed_updates=["message"], tasks_concurrency_limit=24)
    finally:
        await bot.session.close()
