from analyst.controllers.base import AuditedCreateController
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import BulletinAttachment
from analyst.serializers import BulletinAttachmentSerializer


class BulletinAttachmentCreateController(AuditedCreateController):
    queryset = BulletinAttachment.objects.all()
    serializer_class = BulletinAttachmentSerializer
    permission_classes = (IsAdminOrAnalyst,)
    audit_action = "BULLETIN_ATTACHMENT_CREATED"
