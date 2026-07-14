from rest_framework import serializers

from analyst.models import BulletinFinding


class BulletinFindingSerializer(serializers.ModelSerializer):
    peer_ip = serializers.CharField(source="peer_ip_snapshot", read_only=True)
    peer_country = serializers.CharField(source="peer_country_snapshot", read_only=True)
    host_ip = serializers.IPAddressField(source="host_ip_snapshot", read_only=True)
    host_port = serializers.IntegerField(source="host_port_snapshot", read_only=True)
    host_service = serializers.CharField(source="host_service_snapshot", read_only=True)
    host_port_category = serializers.CharField(source="host_port_category_snapshot", read_only=True)
    risk_name = serializers.CharField(source="risk_name_snapshot", read_only=True)

    class Meta:
        model = BulletinFinding
        fields = "__all__"
        read_only_fields = BulletinFinding.SNAPSHOT_FIELDS

    def validate(self, attrs):
        if self.instance:
            observation = attrs.get("peer_observation", self.instance.peer_observation)
            risk_profile = attrs.get("risk_profile", self.instance.risk_profile)
            if observation.pk != self.instance.peer_observation_id or risk_profile.pk != self.instance.risk_profile_id:
                raise serializers.ValidationError(
                    "L'observation et le profil de risque d'un constat existant ne peuvent pas être modifiés."
                )
        return attrs
