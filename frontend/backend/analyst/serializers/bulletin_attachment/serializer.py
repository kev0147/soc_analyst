from rest_framework import serializers

from analyst.models import BulletinAttachment


class BulletinAttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = BulletinAttachment
        fields = "__all__"
        read_only_fields = ("uploaded_at",)

