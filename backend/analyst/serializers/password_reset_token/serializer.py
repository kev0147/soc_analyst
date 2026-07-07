from rest_framework import serializers

from analyst.models import PasswordResetToken


class PasswordResetTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordResetToken
        fields = ("id", "user", "created_by", "created_at", "expires_at", "used_at")
        read_only_fields = ("created_by", "created_at", "used_at")

