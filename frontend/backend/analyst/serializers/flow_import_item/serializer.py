from rest_framework import serializers

from analyst.models import FlowImportItem


class FlowImportItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = FlowImportItem
        fields = "__all__"

