from rest_framework import serializers

from analyst.models import BackgroundJob


class BackgroundJobSerializer(serializers.ModelSerializer):
    progress_percent = serializers.FloatField(read_only=True)
    can_retry = serializers.BooleanField(read_only=True)
    can_cancel = serializers.BooleanField(read_only=True)

    class Meta:
        model = BackgroundJob
        fields = "__all__"
        read_only_fields = tuple(field.name for field in BackgroundJob._meta.fields)
