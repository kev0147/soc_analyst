from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import DetectionRule
from analyst.serializers import DetectionRuleSerializer


class DetectionRuleCreateController(AuditedCreateController):
    queryset = DetectionRule.objects.all()
    serializer_class = DetectionRuleSerializer
    permission_classes = (IsAdmin,)
    audit_action = "DETECTION_RULE_CREATED"
