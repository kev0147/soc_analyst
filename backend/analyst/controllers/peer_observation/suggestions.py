from django.db.models import Case, IntegerField, Value, When
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination

from analyst.models import PeerObservation
from analyst.models.choices import ReputationVerdict
from analyst.serializers import PeerObservationSerializer
from .filters import apply_peer_observation_filters


class ObservationSuggestionPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = "limit"
    max_page_size = 500


class PeerObservationSuggestionsController(generics.ListAPIView):
    serializer_class = PeerObservationSerializer
    permission_classes = (IsAuthenticated,)
    pagination_class = ObservationSuggestionPagination

    def get_queryset(self):
        queryset = PeerObservation.objects.select_related("peer_reputation", "network", "network__structure").prefetch_related("peer_reputation__results").annotate(
            verdict_rank=Case(
                When(peer_reputation__verdict=ReputationVerdict.MALICIOUS, then=Value(0)),
                When(peer_reputation__verdict=ReputationVerdict.SUSPICIOUS, then=Value(1)),
                When(peer_reputation__verdict=ReputationVerdict.CLEAN, then=Value(2)),
                default=Value(3),
                output_field=IntegerField(),
            )
        )
        queryset = apply_peer_observation_filters(queryset, self.request.query_params)
        malicious_only = str(self.request.query_params.get("malicious_only", "")).lower() in {"1", "true", "yes"}
        suspicious_only = str(self.request.query_params.get("suspicious_only", "")).lower() in {"1", "true", "yes"}
        if malicious_only:
            queryset = queryset.filter(peer_reputation__verdict=ReputationVerdict.MALICIOUS)
        if suspicious_only:
            queryset = queryset.filter(
                peer_reputation__verdict__in=(ReputationVerdict.MALICIOUS, ReputationVerdict.SUSPICIOUS)
            )
        return queryset.order_by(
            "verdict_rank",
            "-peer_reputation__score",
            "-total_duration_seconds",
            "-flow_count",
            "-total_bytes",
            "-last_seen_at",
        )
