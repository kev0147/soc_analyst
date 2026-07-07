from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers


class ConsumePasswordResetTokenSerializer(serializers.Serializer):
    token = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True, validators=[validate_password])

