from rest_framework import serializers

from analyst.models import BulletinFinding


class BulletinFindingSerializer(serializers.ModelSerializer):
    peer_ip = serializers.CharField(source="peer_observation.peer_ip", read_only=True)
    peer_country = serializers.CharField(source="peer_observation.peer_country", read_only=True)
    host_ip = serializers.IPAddressField(source="peer_observation.host_ip", read_only=True)
    host_port = serializers.IntegerField(source="peer_observation.host_port", read_only=True)
    host_service = serializers.CharField(source="peer_observation.host_service", read_only=True)
    host_port_category = serializers.CharField(source="peer_observation.host_port_category", read_only=True)
    risk_name = serializers.CharField(source="risk_profile.name", read_only=True)

    class Meta:
        model = BulletinFinding
        fields = "__all__"
