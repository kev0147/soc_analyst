from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import RiskIndicator
from analyst.serializers import RiskIndicatorSerializer


class RiskIndicatorListController(generics.ListAPIView):
    serializer_class = RiskIndicatorSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = RiskIndicator.objects.all()
        is_active = self.request.query_params.get("is_active")
        if is_active in ("true", "false"):
            queryset = queryset.filter(is_active=is_active == "true")
        port = self.request.query_params.get("host_port") or self.request.query_params.get("port")
        if port:
            try:
                queryset = queryset.filter(risk_profile_links__risk_profile__port_services__port=int(port))
            except ValueError:
                return queryset.none()
        search = self.request.query_params.get("search")
        if search:
            queryset = queryset.filter(name__icontains=search.strip())
        return queryset.distinct()
