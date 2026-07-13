from rest_framework import serializers

from analyst.models import (
    Bulletin,
    BulletinTypeCatalog,
    Network,
    PeerObservation,
    RecommendationCatalog,
    RiskCatalog,
    RiskProfile,
    Structure,
)
from analyst.models.choices import BulletinIPRole


class BulletinSerializer(serializers.ModelSerializer):
    ips = serializers.SerializerMethodField()
    risks = serializers.SerializerMethodField()
    bulletin_types = serializers.SerializerMethodField()
    recommendations = serializers.SerializerMethodField()
    findings = serializers.SerializerMethodField()

    class Meta:
        model = Bulletin
        fields = "__all__"
        read_only_fields = (
            "reference_year", "sequence_number", "reference", "ip_signature",
            "created_by", "updated_by", "created_at", "updated_at", "deleted_at", "deleted_by",
        )

    def get_ips(self, obj):
        return [
            {"id": item.id, "ip_address": item.ip_address, "role": item.role, "port": item.port, "note": item.note}
            for item in obj.ip_addresses.all()
        ]

    def get_risks(self, obj):
        return [{"id": link.risk_id, "name": link.risk.name} for link in obj.risk_links.all()]

    def get_bulletin_types(self, obj):
        return [{"id": link.bulletin_type_id, "name": link.bulletin_type.name} for link in obj.type_links.all()]

    def get_recommendations(self, obj):
        return [
            {"id": link.recommendation_id, "name": link.recommendation.name, "description": link.recommendation.description}
            for link in obj.recommendation_links.all()
        ]

    def get_findings(self, obj):
        return [
            {
                "id": finding.id,
                "peer_observation_id": finding.peer_observation_id,
                "peer_ip": finding.peer_observation.peer_ip,
                "peer_country": finding.peer_observation.peer_country,
                "host_ip": finding.peer_observation.host_ip,
                "host_port": finding.peer_observation.host_port,
                "host_service": finding.peer_observation.host_service,
                "host_port_category": finding.peer_observation.host_port_category,
                "flow_count": finding.peer_observation.flow_count,
                "total_bytes": finding.peer_observation.total_bytes,
                "total_packets": finding.peer_observation.total_packets,
                "total_duration_seconds": finding.peer_observation.total_duration_seconds,
                "max_duration_seconds": finding.peer_observation.max_duration_seconds,
                "avg_duration_seconds": finding.peer_observation.avg_duration_seconds,
                "reputation_verdict": finding.peer_observation.peer_reputation.verdict,
                "reputation_score": finding.peer_observation.peer_reputation.score,
                "risk_profile_id": finding.risk_profile_id,
                "risk_name": finding.risk_profile.name,
                "severity": finding.severity,
                "impact": finding.impact_snapshot,
                "recommendation": finding.recommendation_snapshot,
                "note": finding.note,
            }
            for finding in obj.findings.select_related(
                "peer_observation",
                "peer_observation__peer_reputation",
                "risk_profile",
            ).all()
        ]


class BulletinIPInputSerializer(serializers.Serializer):
    ip_address = serializers.IPAddressField(protocol="IPv4")
    role = serializers.ChoiceField(choices=BulletinIPRole.choices)
    port = serializers.IntegerField(required=False, allow_null=True, min_value=0, max_value=65535)
    note = serializers.CharField(required=False, allow_blank=True, max_length=255)


class BulletinCreateInputSerializer(serializers.Serializer):
    structure_id = serializers.PrimaryKeyRelatedField(queryset=Structure.objects.filter(is_active=True), source="structure")
    network_id = serializers.PrimaryKeyRelatedField(
        queryset=Network.objects.filter(is_active=True),
        source="network",
        required=False,
        allow_null=True,
    )
    external_reference = serializers.CharField(required=False, allow_blank=True, max_length=128)
    severity = serializers.ChoiceField(choices=Bulletin._meta.get_field("severity").choices)
    status = serializers.ChoiceField(choices=Bulletin._meta.get_field("status").choices, required=False)
    sent_at = serializers.DateTimeField(required=False, allow_null=True)
    ips = BulletinIPInputSerializer(many=True)
    risk_ids = serializers.PrimaryKeyRelatedField(
        queryset=RiskCatalog.objects.filter(is_active=True),
        source="risks",
        many=True,
    )
    bulletin_type_ids = serializers.PrimaryKeyRelatedField(
        queryset=BulletinTypeCatalog.objects.filter(is_active=True),
        source="bulletin_types",
        many=True,
        required=False,
        default=list,
    )
    recommendation_ids = serializers.PrimaryKeyRelatedField(
        queryset=RecommendationCatalog.objects.filter(is_active=True),
        source="recommendations",
        many=True,
        required=False,
        default=list,
    )
    force_duplicate = serializers.BooleanField(required=False, default=False)

    def validate_ips(self, value):
        if not value:
            raise serializers.ValidationError("Au moins une IP doit être renseignée.")
        seen = set()
        duplicates = []
        for item in value:
            key = (item["ip_address"], item["role"], item.get("port"))
            if key in seen:
                duplicates.append(f"{item['ip_address']}:{item.get('port') or '-'} ({item['role']})")
            seen.add(key)
        if duplicates:
            raise serializers.ValidationError(
                "Une IP ne peut pas être déclarée plusieurs fois dans le même bulletin."
            )
        return value

    def validate_risks(self, value):
        if not value:
            raise serializers.ValidationError("Au moins un risque doit être lié au bulletin.")
        return value

    def validate(self, attrs):
        network = attrs.get("network")
        structure = attrs.get("structure")
        if network and structure and network.structure_id != structure.id:
            raise serializers.ValidationError({"network_id": "Le réseau doit appartenir à la structure du bulletin."})
        return attrs


class BulletinFromFindingsInputSerializer(serializers.Serializer):
    structure_id = serializers.PrimaryKeyRelatedField(queryset=Structure.objects.filter(is_active=True), source="structure")
    network_id = serializers.PrimaryKeyRelatedField(
        queryset=Network.objects.filter(is_active=True),
        source="network",
        required=False,
        allow_null=True,
    )
    external_reference = serializers.CharField(required=False, allow_blank=True, max_length=128)
    severity = serializers.ChoiceField(choices=Bulletin._meta.get_field("severity").choices, required=False)
    status = serializers.ChoiceField(choices=Bulletin._meta.get_field("status").choices, required=False)
    sent_at = serializers.DateTimeField(required=False, allow_null=True)
    peer_observation_ids = serializers.PrimaryKeyRelatedField(
        queryset=PeerObservation.objects.select_related("network", "network__structure"),
        source="peer_observations",
        many=True,
    )
    risk_profile_ids = serializers.PrimaryKeyRelatedField(
        queryset=RiskProfile.objects.filter(is_active=True),
        source="risk_profiles",
        many=True,
    )
    force_duplicate = serializers.BooleanField(required=False, default=False)

    def validate_peer_observation_ids(self, value):
        if not value:
            raise serializers.ValidationError("Au moins une observation peer doit être renseignée.")
        return value

    def validate_risk_profile_ids(self, value):
        if not value:
            raise serializers.ValidationError("Au moins un profil de risque doit être renseigné.")
        return value

    def validate(self, attrs):
        structure = attrs["structure"]
        network = attrs.get("network")
        observations = attrs.get("peer_observations", [])

        invalid_structure = [
            observation.id for observation in observations if observation.network.structure_id != structure.id
        ]
        if invalid_structure:
            raise serializers.ValidationError(
                {"peer_observation_ids": "Toutes les observations doivent appartenir à la structure du bulletin."}
            )

        if network:
            if network.structure_id != structure.id:
                raise serializers.ValidationError({"network_id": "Le réseau doit appartenir à la structure du bulletin."})
            invalid_network = [observation.id for observation in observations if observation.network_id != network.id]
            if invalid_network:
                raise serializers.ValidationError(
                    {"peer_observation_ids": "Toutes les observations doivent appartenir au réseau choisi."}
                )
        return attrs
