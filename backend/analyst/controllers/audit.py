from analyst.models import AuditEvent


def record_audit(request, action, instance=None, details=None):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    ip_address = forwarded.split(",")[0].strip() if forwarded else request.META.get("REMOTE_ADDR")
    AuditEvent.objects.create(
        actor=request.user if request.user.is_authenticated else None,
        action=action,
        entity_type=instance._meta.label_lower if instance else "",
        entity_id=str(instance.pk) if instance and instance.pk is not None else "",
        ip_address=ip_address or None,
        details=details or {},
    )

