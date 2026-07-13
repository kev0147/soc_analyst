from rest_framework import generics
from rest_framework.response import Response

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import Bulletin
from analyst.serializers import BulletinSerializer


class BulletinRestoreController(generics.GenericAPIView):
    queryset = Bulletin.objects.all()
    serializer_class = BulletinSerializer
    permission_classes = (IsAdminOrAnalyst,)

    def post(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.deleted_at = None
        instance.deleted_by = None
        instance.updated_by = request.user
        instance.save(update_fields=("deleted_at", "deleted_by", "updated_by", "updated_at"))
        record_audit(request, "BULLETIN_RESTORED", instance)
        return Response(self.get_serializer(instance).data)
