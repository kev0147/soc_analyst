from rest_framework import serializers

from analyst.models import DailyFlowAggregate


class DailyFlowAggregateSerializer(serializers.ModelSerializer):
    structure_code = serializers.CharField(source="structure.code", read_only=True)
    network_name = serializers.CharField(source="network.name", read_only=True)

    class Meta:
        model = DailyFlowAggregate
        fields = "__all__"
        read_only_fields = tuple(field.name for field in DailyFlowAggregate._meta.fields)
