from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from django.db.models import Prefetch

from analyst.models import RiskProfile, RiskProfileIndicator
from analyst.serializers import RiskProfileSerializer


class RiskProfileListController(generics.ListAPIView):
    serializer_class = RiskProfileSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = RiskProfile.objects.prefetch_related(
            "port_services",
            Prefetch("indicator_links", queryset=RiskProfileIndicator.objects.select_related("indicator")),
        )
        is_active = self.request.query_params.get("is_active")
        if is_active in ("true", "false"):
            queryset = queryset.filter(is_active=is_active == "true")
        port = self.request.query_params.get("host_port") or self.request.query_params.get("port")
        if port:
            try:
                queryset = queryset.filter(port_services__port=int(port))
            except ValueError:
                return queryset.none()
        indicator_id = self.request.query_params.get("indicator_id")
        if indicator_id:
            queryset = queryset.filter(indicator_links__indicator_id=indicator_id)
        activity = self.request.query_params.get("activity")
        if activity:
            queryset = queryset.filter(activity__icontains=activity.strip())
        return queryset.distinct()
