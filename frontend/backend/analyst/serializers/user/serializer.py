from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from analyst.models import User


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, validators=[validate_password])

    class Meta:
        model = User
        fields = (
            "id", "email", "display_name", "role", "is_active", "password",
            "last_login", "date_joined", "updated_at",
        )
        read_only_fields = ("last_login", "date_joined", "updated_at")

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        if not password:
            raise serializers.ValidationError({"password": "Ce champ est obligatoire."})
        return User.objects.create_user(password=password, **validated_data)

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        instance = super().update(instance, validated_data)
        if password:
            instance.set_password(password)
            instance.save(update_fields=("password",))
        return instance
