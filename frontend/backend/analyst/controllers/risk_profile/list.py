from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import RiskProfile
from analyst.serializers import RiskProfileSerializer


class RiskProfileListController(generics.ListAPIView):
    serializer_class = RiskProfileSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = RiskProfile.objects.all()
        is_active = self.request.query_params.get("is_active")
        if is_active in ("true", "false"):
            queryset = queryset.filter(is_active=is_active == "true")
        return queryset
