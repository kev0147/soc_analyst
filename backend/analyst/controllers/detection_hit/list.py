from django.db.models import Case, IntegerField, Value, When
from django.utils.dateparse import parse_date
from rest_framework import generics
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated

from analyst.models import DetectionHit
from analyst.serializers import DetectionHitSerializer


ALLOWED_ORDERING = {
    "last_seen_at",
    "first_seen_at",
    "last_detected_at",
    "observation_date",
    "severity",
    "flow_count",
    "total_bytes",
    "total_duration_seconds",
    "reputation_score",
}


class DetectionHitListController(generics.ListAPIView):
    serializer_class = DetectionHitSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = DetectionHit.objects.select_related("rule", "structure", "network")
        params = self.request.query_params
        for name in ("structure_id", "rule_id"):
            if params.get(name):
                try:
                    queryset = queryset.filter(**{name: int(params[name])})
                except ValueError as exc:
                    raise ValidationError({name: "Doit être un entier."}) from exc
        for name in ("status", "severity", "peer_ip", "host_ip"):
            if params.get(name):
                queryset = queryset.filter(**{name: params[name]})
        date_from = parse_date(params.get("date_from", ""))
        date_to = parse_date(params.get("date_to", ""))
        if params.get("date_from") and not date_from:
            raise ValidationError({"date_from": "Date invalide."})
        if params.get("date_to") and not date_to:
            raise ValidationError({"date_to": "Date invalide."})
        if date_from:
            queryset = queryset.filter(observation_date__gte=date_from)
        if date_to:
            queryset = queryset.filter(observation_date__lte=date_to)
        ordering = params.get("ordering") or "-last_seen_at"
        field = ordering[1:] if ordering.startswith("-") else ordering
        if field not in ALLOWED_ORDERING:
            raise ValidationError({"ordering": "Tri non autorisé."})
        if field == "severity":
            queryset = queryset.annotate(
                severity_rank=Case(
                    When(severity="critical", then=Value(4)),
                    When(severity="high", then=Value(3)),
                    When(severity="medium", then=Value(2)),
                    default=Value(1),
                    output_field=IntegerField(),
                )
            )
            ordering = "-severity_rank" if ordering.startswith("-") else "severity_rank"
        return queryset.order_by(ordering, "-id")
