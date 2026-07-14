import re
from datetime import datetime, timezone
from typing import Any


NULL_MARKERS = {"", "--", "n/a", "na", "null", "none"}
UNIT_MULTIPLIERS = {
    "K": 1_000,
    "M": 1_000_000,
    "G": 1_000_000_000,
    "T": 1_000_000_000_000,
}
NEGATIVE_SENTINELS = {
    "TCP Retransmissions": {"-1"},
    "TCP Retransmission Ratio": {"-0.01"},
}


def clean_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    if cleaned.lower() in NULL_MARKERS:
        return None
    return cleaned


def text_or_blank(value: Any) -> str:
    return clean_text(value) or ""


def number(value: Any, column: str | None = None) -> float | None:
    cleaned = clean_text(value)
    if cleaned is None:
        return None
    if column and cleaned in NEGATIVE_SENTINELS.get(column, set()):
        return None

    normalized = cleaned.replace(" ", "")
    match = re.fullmatch(r"([-+]?\d+(?:\.\d+)?)([KMGTkmgt]?)", normalized)
    if not match:
        return None

    base = float(match.group(1))
    unit = match.group(2).upper()
    return base * UNIT_MULTIPLIERS.get(unit, 1)


def integer(value: Any, column: str | None = None) -> int | None:
    parsed = number(value, column=column)
    if parsed is None:
        return None
    if parsed < 0:
        return None
    return int(round(parsed))


def floating(value: Any, column: str | None = None) -> float | None:
    parsed = number(value, column=column)
    if parsed is None:
        return None
    return float(parsed)


def datetime_utc(value: Any) -> datetime | None:
    cleaned = clean_text(value)
    if cleaned is None:
        return None
    normalized = cleaned
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    if re.search(r"[+-]\d{4}$", normalized):
        normalized = f"{normalized[:-5]}{normalized[-5:-2]}:{normalized[-2:]}"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        try:
            parsed = datetime.strptime(normalized, "%a %b %d %H:%M:%S %Z %Y")
        except ValueError:
            return None
        parsed = parsed.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def duration_seconds(value: Any) -> int | None:
    cleaned = clean_text(value)
    if cleaned is None:
        return None

    total = 0
    for amount, unit in re.findall(r"(\d+(?:\.\d+)?)\s*(d|day|days|h|hr|hrs|hour|hours|min|mins|m|sec|secs|s)", cleaned, re.I):
        parsed = float(amount)
        normalized_unit = unit.lower()
        if normalized_unit in {"d", "day", "days"}:
            total += int(parsed * 86_400)
        elif normalized_unit in {"h", "hr", "hrs", "hour", "hours"}:
            total += int(parsed * 3_600)
        elif normalized_unit in {"min", "mins", "m"}:
            total += int(parsed * 60)
        else:
            total += int(parsed)
    if total:
        return total

    parsed_number = number(cleaned)
    return int(parsed_number) if parsed_number is not None else None


def port_protocol(value: Any) -> tuple[int | None, str]:
    cleaned = clean_text(value)
    if cleaned is None:
        return None, ""
    if "/" in cleaned:
        port_part, protocol_part = cleaned.split("/", 1)
        return integer(port_part), protocol_part.strip().upper()
    return integer(cleaned), ""
