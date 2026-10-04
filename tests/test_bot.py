import asyncio
from html import unescape
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from aiogram import Bot, Dispatcher
from aiogram.types import Chat, ChatFullInfo, Message
from aiogram.exceptions import TelegramBadRequest, TelegramNetworkError
from aiogram.methods import GetChat

from osint_bot.bot import RateLimiter, build_router
from osint_bot.config import Config, load_env
from osint_bot.parser import QueryError, parse_query
from osint_bot.reports import Card
from osint_bot.service import LookupService, valid_inn, valid_ogrn
from osint_bot.sources import SourceClient, SourceError


TEST_CHAT_FIELDS = {
    "accent_color_id": 0,
    "max_reaction_count": 11,
    "accepted_gift_types": {"unlimited_gifts": False, "limited_gifts": False,
                            "unique_gifts": False, "premium_subscription": False,
                            "gifts_from_channels": False},
}


class ParserTests(unittest.TestCase):
    def test_examples(self):
        cases = {
            "Навальный Алексей Анатольевич 04.06.1976": "restricted",
            "79999688666": "phone", "79999688666@mail.ru": "email",
            "В395ОК199": "plate", "XTA211440C5106924": "vin",
            "vk.com/sherlock": "social", "tiktok.com/@sherlock": "social",
            "instagram.com/sherlock": "social", "ok.ru/profile/58460": "social",
            "@sherlock": "username", "tg123456": "telegram_id",
            "/vu 1234567890": "restricted", "/passport 1234567890": "restricted",
            "/snils 12345678901": "restricted", "/inn 123456789012": "inn",
            "/tag хирург москва": "restricted", "sherlock.com": "domain",
            "1.1.1.1": "ip", "/adr Город, Улица, 1": "restricted",
            "77:01:0004042:6987": "cadastre", "/inn 2540214547": "inn",
            "1107449004464": "ogrn", "2606:4700:4700::1111": "ip",
            "https://t.me/sherlock": "social", "github.com/octocat": "social",
            "/phone +1234567890123": "phone", "/phone 123456789012345": "phone",
            "vk.com@example.com": "email",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(parse_query(text).kind, expected)

    def test_special_and_private_addresses_rejected(self):
        for text in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "0.0.0.0", "192.0.2.1", "::1",
                     "fc00::1", "https://127.0.0.1/", "example.local", "abc.onion", "999.1.1.1"):
            with self.subTest(text=text), self.assertRaises(QueryError):
                parse_query(text)

    def test_urls_and_input_validation(self):
        for text in ("https://user:password@example.com", "https://example.com:8080", "https://t.me/+invite",
                     "https://t.me/c/1234", "t.me/name/42", "@name<script>", "example.com\nsecret", "x" * 513,
                     "/vin INVALID", "/email test..name@example.com", "/inn 123", "/unknown text"):
            with self.subTest(text=text), self.assertRaises(QueryError):
                parse_query(text)
        self.assertEqual(parse_query("https://vk.com.evil.example/person").kind, "domain")
        self.assertEqual(parse_query("https://example.com/path?secret=x").value, "example.com")
        self.assertEqual(parse_query("пример.рф").value, "xn--e1afmkfd.xn--p1ai")
        self.assertEqual(parse_query("/start@my_bot").kind, "start")

    def test_sensitive_identifier_not_retained(self):
        self.assertEqual(parse_query("/passport 1234567890").value, "/passport")
        self.assertEqual(parse_query("Иванов Иван Иванович 01.01.1980").value, "person")


class LocalTests(unittest.TestCase):
    def test_business_checksums(self):
        self.assertTrue(valid_inn("7707083893"))
        self.assertFalse(valid_inn("7707083894"))
        self.assertFalse(valid_inn("0000000000"))
        self.assertTrue(valid_ogrn("1027700132195"))
        self.assertFalse(valid_ogrn("1027700132196"))
        self.assertFalse(valid_ogrn("0000000000000"))

    def test_rate_limit_window_and_bounded_memory(self):
        limiter = RateLimiter(2, max_users=2)
        self.assertEqual(limiter.check(1, 0), (True, False))
        self.assertEqual(limiter.check(1, 1), (True, False))
        self.assertEqual(limiter.check(1, 2), (False, True))
        self.assertEqual(limiter.check(1, 3), (False, False))
        self.assertEqual(limiter.check(1, 60), (True, False))
        limiter.check(2, 60)
        limiter.check(3, 60)
        self.assertEqual(len(limiter.users), 2)
        self.assertNotIn(1, limiter.users)

    def test_html_escaping_and_message_length(self):
        card = Card("<script>", ["<img> & \"hello\"", *["&" * 400 for _ in range(20)]],
                    [("<link>", "https://example.com/?a=1&b=2"), ("unsafe", "javascript:alert(1)")])
        result = card.render()
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;img&gt;", result)
        self.assertNotIn("javascript:", result)
        self.assertLess(len(result), 4096)
        self.assertIn("МСК", result)

    def test_env_no_evaluation_and_system_env_precedence(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"BOT_TOKEN": "from_environment"}, clear=True):
            path = Path(directory) / ".env"
            path.write_text("BOT_TOKEN=from_file\nDADATA_API_TOKEN='$(secret)'\n", encoding="utf-8")
            load_env(path)
            import os
            self.assertEqual(os.environ["BOT_TOKEN"], "from_environment")
            self.assertEqual(os.environ["DADATA_API_TOKEN"], "$(secret)")

    def test_secret_fields_not_in_repr(self):
        self.assertNotIn("secret-token", repr(Config(token="secret-token", dadata_token="secret-token", github_token="secret-token")))


class SourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_email_shares_only_domain(self):
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 15, "data": "10 mx.example.com."}]})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cards = await LookupService(SourceClient(client), Config()).lookup(parse_query("private.local.part@example.com"))
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].url.params["name"], "example.com")
        self.assertNotIn("private.local.part", str(requests[0].url))
        self.assertIn("MX: 10 mx.example.com.", cards[0].render())

    async def test_phone_and_individual_identifiers_stay_local(self):
        async def forbidden(request):
            self.fail("Unexpected external request")
        async with httpx.AsyncClient(transport=httpx.MockTransport(forbidden)) as client:
            service = LookupService(SourceClient(client), Config())
            for text in ("/phone +79999688666", "/inn 123456789012", "tg123456", "/passport 1234567890"):
                cards = await service.lookup(parse_query(text))
                self.assertTrue(cards)

    async def test_iana_bootstrap_routing_cache_and_private_redirect_block(self):
        requests = []
        def handler(request):
            requests.append(request)
            if request.url.host == "data.iana.org":
                return httpx.Response(200, json={"services": [[["com"], ["https://registry.example/rdap/"]]]})
            return httpx.Response(302, headers={"Location": "https://127.0.0.1/secret"})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            sources = SourceClient(client)
            for _ in range(2):
                with self.assertRaises(SourceError):
                    await sources.rdap("example.com", "domain")
        self.assertEqual([r.url.host for r in requests], ["data.iana.org", "registry.example", "registry.example"])
        self.assertEqual(requests[1].url.path, "/rdap/domain/example.com")

    async def test_ip_bootstrap_uses_matching_network(self):
        requests = []
        def handler(request):
            requests.append(request)
            if request.url.host == "data.iana.org":
                return httpx.Response(200, json={"services": [
                    [["1.0.0.0/8"], ["https://registry.example/"]],
                    [["8.0.0.0/8"], ["https://other.example/"]]]})
            return httpx.Response(200, json={"name": "CLOUDFLARE", "country": "AU"})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result, _ = await SourceClient(client).rdap("1.1.1.1", "ip")
        self.assertEqual(result["name"], "CLOUDFLARE")
        self.assertEqual(requests[-1].url.host, "registry.example")

    async def test_partial_dns_failures_keep_successful_records(self):
        def handler(request):
            if request.url.host == "data.iana.org":
                return httpx.Response(503)
            kind = request.url.params.get("type")
            if kind == "AAAA":
                return httpx.Response(429)
            return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 1, "data": "1.1.1.1"}]})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cards = await LookupService(SourceClient(client), Config()).lookup(parse_query("example.com"))
        self.assertIn("A: 1.1.1.1", cards[0].render())
        self.assertIn("Лимит", cards[0].render())
        self.assertEqual(len(cards), 2)

    async def test_http_errors_do_not_expose_credentials(self):
        def handler(request):
            raise httpx.ConnectError("Token SECRET appeared in connection", request=request)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with self.assertRaises(SourceError) as raised:
                await SourceClient(client).company("7707083893", "SECRET")
        self.assertNotIn("SECRET", str(raised.exception))

    async def test_dadata_only_legal_entities(self):
        def handler(request):
            self.assertEqual(__import__("json").loads(request.content)["type"], "LEGAL")
            return httpx.Response(200, json={"suggestions": [{"data": {"type": "INDIVIDUAL", "name": "Person"}}]})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cards = await LookupService(SourceClient(client), Config(dadata_token="TEST")).lookup(parse_query("/inn 7707083893"))
        self.assertNotIn("Person", cards[0].render())

    async def test_profile_links_are_not_claimed_verified(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as client:
            cards = await LookupService(SourceClient(client), Config()).lookup(parse_query("vk.com/sherlock"))
        self.assertIn("не проверены", cards[0].render())

    async def test_public_telegram_card_for_channel_and_group(self):
        for chat_type, label in (("channel", "публичный канал"), ("supergroup", "публичная группа")):
            with self.subTest(chat_type=chat_type):
                bot = AsyncMock()
                bot.get_chat.return_value = ChatFullInfo(
                    id=-1001234567890, type=chat_type, username="PublicDemo",
                    title="Public <b>demo</b>", description="About <script>demo</script>",
                    **TEST_CHAT_FIELDS)
                async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as client:
                    cards = await LookupService(SourceClient(client), Config()).lookup(parse_query("t.me/publicdemo"), bot)
                bot.get_chat.assert_awaited_once_with("@publicdemo")
                report = cards[0].render()
                self.assertIn("ID канала/группы: -1001234567890", report)
                self.assertIn("@PublicDemo", report)
                self.assertIn(label, report)
                self.assertIn("Public &lt;b&gt;demo&lt;/b&gt;", report)
                self.assertNotIn("<script>", report)
                self.assertIn("https://core.telegram.org/bots/api#getchat", report)

    async def test_telegram_card_excludes_private_and_direct_message_chats(self):
        chats = [
            ChatFullInfo(id=123456, type="private", first_name="PRIVATE_NAME",
                         bio="PRIVATE_BIO", **TEST_CHAT_FIELDS),
            ChatFullInfo(id=-100654321, type="supergroup", title="PRIVATE_NAME",
                         description="PRIVATE_BIO", is_direct_messages=True,
                         **TEST_CHAT_FIELDS),
        ]
        async with httpx.AsyncClient() as client:
            service = LookupService(SourceClient(client), Config())
            for chat in chats:
                with self.subTest(chat_type=chat.type):
                    bot = AsyncMock()
                    bot.get_chat.return_value = chat
                    report = (await service._telegram_card("publicdemo", bot)).render()
                    self.assertNotIn(str(chat.id), report)
                    self.assertNotIn("PRIVATE_NAME", report)
                    self.assertNotIn("PRIVATE_BIO", report)
                    self.assertIn("не подтверждены", report)

    async def test_telegram_card_errors_and_missing_description(self):
        async with httpx.AsyncClient() as client:
            service = LookupService(SourceClient(client), Config())
            bot = AsyncMock()
            bot.get_chat.return_value = ChatFullInfo(id=-100123456, type="channel", username="publicdemo",
                                                    **TEST_CHAT_FIELDS)
            report = (await service._telegram_card("publicdemo", bot)).render()
            self.assertIn("Описание: не указано", report)
            for error, expected in (
                (TelegramBadRequest(method=GetChat(chat_id="@publicdemo"), message="chat not found"), "не означает, что аккаунт отсутствует"),
                (TelegramNetworkError(method=GetChat(chat_id="@publicdemo"), message="SECRET"), "сейчас недоступен"),
            ):
                with self.subTest(error=type(error).__name__):
                    bot.get_chat.side_effect = error
                    report = (await service._telegram_card("publicdemo", bot)).render()
                    self.assertIn(expected, report)
                    self.assertNotIn("SECRET", report)
                    self.assertNotIn("ID канала/группы", report)
            report = (await service._telegram_card("publicdemo", None)).render()
            self.assertIn("не проверено", report)

    async def test_at_username_includes_public_telegram_card(self):
        bot = AsyncMock()
        bot.get_chat.return_value = ChatFullInfo(id=-100123456, type="channel", username="publicdemo",
                                                title="Public demo", **TEST_CHAT_FIELDS)
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as client:
            cards = await LookupService(SourceClient(client), Config()).lookup(parse_query("@publicdemo"), bot)
        telegram_cards = [card for card in cards if card.title.startswith("📟 Telegram")]
        self.assertEqual(len(telegram_cards), 1)
        self.assertIn("ID канала/группы: -100123456", telegram_cards[0].render())

    async def test_github_profile_and_token_routing(self):
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"login": "octocat", "name": "<script>name</script>",
                                            "bio": "Public bio", "public_repos": 8, "created_at": "2011-01-25"})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cards = await LookupService(SourceClient(client), Config(github_token="TEST_ONLY")).lookup(parse_query("github.com/octocat"))
        self.assertEqual(requests[0].url.host, "api.github.com")
        self.assertEqual(requests[0].headers["Authorization"], "Bearer TEST_ONLY")
        self.assertIn("Публичный профиль найден", cards[0].render())
        self.assertNotIn("<script>", cards[0].render())
        self.assertNotIn("TEST_ONLY", cards[0].render())

    async def test_nxdomain_and_null_mx_preserved(self):
        for data, expected in [({"Status": 3}, "NXDOMAIN"),
                               ({"Status": 0, "Answer": [{"type": 15, "data": "0 ."}]}, "0 .")]:
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=data))) as client:
                cards = await LookupService(SourceClient(client), Config()).lookup(parse_query("test@example.com"))
            self.assertIn(expected, cards[0].render())
            if expected == "0 .":
                self.assertIn("не принимает электронную почту", cards[0].render())


class TelegramTests(unittest.IsolatedAsyncioTestCase):
    async def dispatch(self, text=None, *, photo=False, config=None, chat_type="private"):
        bot = Bot("12345678:" + "A" * 35)
        bot.session = AsyncMock(return_value=Message(message_id=2, date=0, chat=Chat(id=42, type="private"), text="reply"))
        service = AsyncMock()
        service.lookup.return_value = [Card("Проверка", ["Готово"])]
        dispatcher = Dispatcher()
        dispatcher.include_router(build_router(config or Config(), service))
        message = {"message_id": 1, "date": 0, "chat": {"id": 42, "type": chat_type},
                   "from": {"id": 42, "is_bot": False, "first_name": "Test"}}
        if text is not None:
            message["text"] = text
        if photo:
            message["photo"] = [{"file_id": "TEST_FILE", "file_unique_id": "TEST_UNIQUE", "width": 100, "height": 100}]
        await dispatcher.feed_raw_update(bot, {"update_id": 1, "message": message})
        return bot, service

    async def test_text_routes_and_sends_report(self):
        bot, service = await self.dispatch("example.com")
        service.lookup.assert_awaited_once()
        methods = [call.args[1] for call in bot.session.call_args_list]
        self.assertEqual([type(m).__name__ for m in methods], ["SendChatAction", "SendMessage"])
        self.assertIn("Готово", methods[-1].text)

    async def test_start_shows_russian_keyboard_without_lookup(self):
        bot, service = await self.dispatch("/start")
        service.lookup.assert_not_awaited()
        self.assertIn("Открытый след", bot.session.call_args.args[1].text)
        self.assertIsNotNone(bot.session.call_args.args[1].reply_markup)

    async def test_allowlist_blocks_external_lookup(self):
        bot, service = await self.dispatch("example.com", config=Config(allowed_user_ids=frozenset({99})))
        service.lookup.assert_not_awaited()
        self.assertIn("ограничен", bot.session.call_args.args[1].text)

    async def test_group_messages_ignored(self):
        bot, service = await self.dispatch("example.com", chat_type="group")
        service.lookup.assert_not_awaited()
        bot.session.assert_not_awaited()

    async def test_photo_not_downloaded(self):
        bot, service = await self.dispatch(photo=True)
        service.lookup.assert_not_awaited()
        methods = [type(call.args[1]).__name__ for call in bot.session.call_args_list]
        self.assertEqual(methods, ["SendMessage"])
        self.assertIn("не скачивается", bot.session.call_args.args[1].text)


if __name__ == "__main__":
    unittest.main()
