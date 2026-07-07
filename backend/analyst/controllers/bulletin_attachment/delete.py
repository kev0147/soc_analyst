from analyst.controllers.base import AuditedDestroyController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinAttachment


class BulletinAttachmentDeleteController(AuditedDestroyController):
    queryset = BulletinAttachment.objects.all()
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_ATTACHMENT_DELETED"
