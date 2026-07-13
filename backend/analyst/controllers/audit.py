from analyst.models import AuditEvent
from analyst.services.security import AUDIT_ACTIONS


def record_audit(request, action, instance=None, details=None):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    ip_address = forwarded.split(",")[0].strip() if forwarded else request.META.get("REMOTE_ADDR")
    enriched_details = dict(details or {})
    enriched_details.setdefault("known_action", action in AUDIT_ACTIONS)
    if request.user.is_authenticated:
        enriched_details.setdefault("actor_role", getattr(request.user, "role", ""))
    user_agent = request.META.get("HTTP_USER_AGENT", "")
    if user_agent:
        enriched_details.setdefault("user_agent", user_agent[:300])
    AuditEvent.objects.create(
        actor=request.user if request.user.is_authenticated else None,
        action=action,
        entity_type=instance._meta.label_lower if instance else "",
        entity_id=str(instance.pk) if instance and instance.pk is not None else "",
        ip_address=ip_address or None,
        details=enriched_details,
    )
