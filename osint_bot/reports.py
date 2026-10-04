from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from html import escape
from urllib.parse import urlsplit


@dataclass
class Card:
    title: str
    lines: list[str] = field(default_factory=list)
    links: list[tuple[str, str]] = field(default_factory=list)

    def render(self) -> str:
        parts = ["<b>" + escape(self.title[:120]) + "</b>"]
        size = len(parts[0])
        for line in self.lines:
            item = escape(str(line)[:400])
            if size + len(item) > 2700:
                parts.append("… Ответ сокращён; подробности — в источнике.")
                break
            parts.append(item)
            size += len(item) + 1
        for label, url in self.links[:6]:
            try:
                parsed = urlsplit(url)
                if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                    continue
            except ValueError:
                continue
            item = f'<a href="{escape(url, quote=True)}">{escape(label[:80])}</a>'
            if size + len(item) < 3500:
                parts.append(item)
                size += len(item) + 1
        stamp = datetime.now(timezone(timedelta(hours=3))).strftime("%d.%m.%Y %H:%M МСК")
        parts.append("\n" + stamp)
        return "\n".join(parts)
