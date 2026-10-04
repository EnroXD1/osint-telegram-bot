from dataclasses import dataclass, field
from pathlib import Path
import os
import re


ROOT = Path(__file__).resolve().parent.parent


def load_env(path: Path = ROOT / ".env") -> None:
    """Read simple KEY=value entries, with no evaluation or interpolation."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key.strip()):
            raise ValueError("Неверная строка в .env. Используйте KEY=value.")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


@dataclass(frozen=True)
class Config:
    token: str = field(default="", repr=False)
    allowed_user_ids: frozenset[int] = frozenset()
    dadata_token: str = field(default="", repr=False)
    phone_region: str = "RU"
    rate_limit: int = 10
    timeout: float = 10.0
    github_token: str = field(default="", repr=False)

    @classmethod
    def from_env(cls) -> "Config":
        load_env()
        try:
            allowed = frozenset(int(x.strip()) for x in os.getenv("ALLOWED_USER_IDS", "").split(",") if x.strip())
            rate = int(os.getenv("REQUESTS_PER_MINUTE", "10"))
            timeout = float(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))
        except ValueError:
            raise ValueError("Проверьте числовые значения в .env.") from None
        if any(x <= 0 for x in allowed) or not 1 <= rate <= 60 or not 1 <= timeout <= 30:
            raise ValueError("ID должен быть положительным; лимит — 1–60; таймаут — 1–30 секунд.")
        region = os.getenv("DEFAULT_PHONE_REGION", "RU").upper()
        if not re.fullmatch(r"[A-Z]{2}", region):
            raise ValueError("DEFAULT_PHONE_REGION должен быть кодом страны: RU, US и т. п.")
        return cls(os.getenv("BOT_TOKEN", "").strip(), allowed,
                   os.getenv("DADATA_API_TOKEN", "").strip(), region, rate, timeout,
                   os.getenv("GITHUB_API_TOKEN", "").strip())
