from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import BulletinAttachment
from analyst.serializers import BulletinAttachmentSerializer


class BulletinAttachmentRetrieveController(generics.RetrieveAPIView):
    queryset = BulletinAttachment.objects.all()
    serializer_class = BulletinAttachmentSerializer
    permission_classes = (IsAuthenticated,)
