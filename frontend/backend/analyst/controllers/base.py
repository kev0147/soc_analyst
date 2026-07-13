from django.utils import timezone
from rest_framework import generics, status
from rest_framework.response import Response

from .audit import record_audit


class AuditedCreateController(generics.CreateAPIView):
    audit_action = "ENTITY_CREATED"

    def perform_create(self, serializer):
        model_fields = {field.name for field in serializer.Meta.model._meta.fields}
        kwargs = {}
        if "created_by" in model_fields:
            kwargs["created_by"] = self.request.user
        if "updated_by" in model_fields:
            kwargs["updated_by"] = self.request.user
        if "uploaded_by" in model_fields:
            kwargs["uploaded_by"] = self.request.user
        instance = serializer.save(**kwargs)
        record_audit(self.request, self.audit_action, instance)


class AuditedUpdateController(generics.UpdateAPIView):
    audit_action = "ENTITY_UPDATED"

    def perform_update(self, serializer):
        model_fields = {field.name for field in serializer.Meta.model._meta.fields}
        kwargs = {"updated_by": self.request.user} if "updated_by" in model_fields else {}
        instance = serializer.save(**kwargs)
        record_audit(self.request, self.audit_action, instance)


class AuditedDestroyController(generics.DestroyAPIView):
    audit_action = "ENTITY_DELETED"

    def perform_destroy(self, instance):
        record_audit(self.request, self.audit_action, instance)
        instance.delete()


class DeactivateController(generics.DestroyAPIView):
    audit_action = "ENTITY_DISABLED"

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.is_active = False
        update_fields = ["is_active"]
        if hasattr(instance, "updated_at"):
            instance.updated_at = timezone.now()
            update_fields.append("updated_at")
        instance.save(update_fields=update_fields)
        record_audit(request, self.audit_action, instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class SoftDeleteBulletinController(generics.DestroyAPIView):
    audit_action = "BULLETIN_DELETED"

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.deleted_at = timezone.now()
        instance.deleted_by = request.user
        instance.save(update_fields=("deleted_at", "deleted_by", "updated_at"))
        record_audit(request, self.audit_action, instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

