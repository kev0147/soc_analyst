from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import DetectionRule
from analyst.serializers import DetectionRuleSerializer


class DetectionRuleListController(generics.ListAPIView):
    serializer_class = DetectionRuleSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = DetectionRule.objects.all()
        is_active = self.request.query_params.get("is_active")
        if is_active in ("true", "false"):
            queryset = queryset.filter(is_active=is_active == "true")
        rule_type = self.request.query_params.get("rule_type")
        if rule_type:
            queryset = queryset.filter(rule_type=rule_type)
        return queryset
