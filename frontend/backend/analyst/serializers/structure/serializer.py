from rest_framework import serializers

from analyst.models import Structure


class StructureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Structure
        fields = "__all__"
        read_only_fields = ("created_at", "updated_at")

