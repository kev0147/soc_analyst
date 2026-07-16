from django.db.models import Case, IntegerField, Value, When
from rest_framework import generics
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated

from analyst.controllers.audit import record_audit
from analyst.models import IPReputation
from analyst.models.choices import ReputationVerdict
from analyst.serializers import IPReputationSerializer


class IPAnalysisRecordsController(generics.ListAPIView):
    serializer_class = IPReputationSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = IPReputation.objects.prefetch_related("results").annotate(
            verdict_rank=Case(
                When(verdict=ReputationVerdict.MALICIOUS, then=Value(0)),
                When(verdict=ReputationVerdict.SUSPICIOUS, then=Value(1)),
                When(verdict=ReputationVerdict.CLEAN, then=Value(2)),
                default=Value(3),
                output_field=IntegerField(),
            )
        )
        verdict = self.request.query_params.get("verdict")
        if verdict:
            queryset = queryset.filter(verdict=verdict)
        ip = self.request.query_params.get("ip")
        if ip:
            queryset = queryset.filter(ip_address__icontains=ip)
        structure_id = self.request.query_params.get("structure_id")
        if structure_id not in (None, ""):
            try:
                structure_id = int(structure_id)
            except (TypeError, ValueError) as exc:
                raise ValidationError({"structure_id": "Doit être un entier."}) from exc
            queryset = queryset.filter(
                observations__network__structure_id=structure_id
            ).distinct()
        country = self.request.query_params.get("country")
        if country:
            queryset = queryset.filter(country__iexact=country)
        source = self.request.query_params.get("source")
        if source:
            queryset = queryset.filter(results__source=source).distinct()
        return queryset.order_by("verdict_rank", "-score", "-last_analyzed_at", "ip_address")

    def list(self, request, *args, **kwargs):
        record_audit(request, "IP_REPUTATION_RECORDS_VIEWED", details={"filters": dict(request.query_params)})
        return super().list(request, *args, **kwargs)
