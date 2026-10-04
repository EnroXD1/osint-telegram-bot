import argparse
import asyncio
import logging
import re
import sys

import httpx

from .config import Config
from .parser import QueryError, parse_query
from .service import LookupService
from .sources import SourceClient, SourceError


async def demo(config: Config, text: str) -> None:
    async with httpx.AsyncClient(timeout=config.timeout, trust_env=False,
                                 headers={"User-Agent": "OpenTraceTelegramBot/1.0"}) as client:
        cards = await asyncio.wait_for(LookupService(SourceClient(client), config).lookup(parse_query(text)), 25)
        for card in cards:
            print(card.render() + "\n")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Telegram-бот для открытых источников")
    parser.add_argument("--demo", metavar="QUERY", help="Проверить запрос без Telegram и токена")
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    # The aiogram polling logger may include full exception text. Keep errors
    # in our handler and never emit transport URLs containing the bot token.
    logging.getLogger("aiogram").disabled = True
    for name in ("aiogram.dispatcher", "aiogram.event"):
        logging.getLogger(name).disabled = True
    try:
        config = Config.from_env()
        if args.demo is not None:
            asyncio.run(demo(config, args.demo))
            return 0
        if not re.fullmatch(r"\d{5,}:[A-Za-z0-9_-]{20,}", config.token):
            print("Добавьте BOT_TOKEN от @BotFather в .env. Токен не нужно отправлять в чат.")
            return 2
        from aiogram.exceptions import TelegramAPIError
        from .bot import run_bot
        try:
            asyncio.run(run_bot(config))
        except TelegramAPIError:
            print("Не удалось подключиться к Telegram. Проверьте токен и соединение.")
            return 1
    except (ValueError, QueryError, SourceError) as error:
        print(str(error))
        return 2
    except asyncio.TimeoutError:
        print("Источник отвечает слишком долго.")
        return 1
    except KeyboardInterrupt:
        print("Бот остановлен.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
