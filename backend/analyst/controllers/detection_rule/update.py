from analyst.controllers.base import AuditedUpdateController
from analyst.controllers.permissions import IsAdmin
from analyst.models import DetectionRule
from analyst.serializers import DetectionRuleSerializer


class DetectionRuleUpdateController(AuditedUpdateController):
    queryset = DetectionRule.objects.all()
    serializer_class = DetectionRuleSerializer
    permission_classes = (IsAdmin,)
    audit_action = "DETECTION_RULE_UPDATED"
