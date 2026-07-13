from rest_framework.exceptions import ValidationError


DEFAULT_LIMIT = 10
MAX_LIMIT = 100


def int_param(params, name: str) -> int | None:
    value = params.get(name)
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError({name: "Doit être un entier."}) from exc


def limit_param(params) -> int:
    value = int_param(params, "limit")
    if value is None:
        return DEFAULT_LIMIT
    if value < 1:
        raise ValidationError({"limit": "Doit être supérieur à 0."})
    return min(value, MAX_LIMIT)


def flow_filter_params_without_ordering(params):
    copied = params.copy()
    copied.pop("ordering", None)
    return copied
