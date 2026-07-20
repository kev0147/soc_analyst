from rest_framework import serializers

from analyst.models import (
    ActivityCatalog,
    Bulletin,
    PeerObservation,
    RecommendationCatalog,
    RiskCatalog,
    RiskIndicator,
    RiskProfile,
    Structure,
)
from analyst.models.choices import BulletinIPRole


class BulletinSerializer(serializers.ModelSerializer):
    ips = serializers.SerializerMethodField()
    risks = serializers.SerializerMethodField()
    activities = serializers.SerializerMethodField()
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

    def get_activities(self, obj):
        return [{"id": link.activity_id, "name": link.activity.name} for link in obj.activity_links.all()]

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
                "peer_ip": finding.peer_ip_snapshot,
                "peer_country": finding.peer_country_snapshot,
                "host_ip": finding.host_ip_snapshot,
                "host_port": finding.host_port_snapshot,
                "host_service": finding.host_service_snapshot,
                "host_port_category": finding.host_port_category_snapshot,
                "network_name": finding.network_name_snapshot,
                "first_seen_at": finding.observation_first_seen_at_snapshot,
                "last_seen_at": finding.observation_last_seen_at_snapshot,
                "flow_count": finding.flow_count_snapshot,
                "total_bytes": finding.total_bytes_snapshot,
                "total_packets": finding.total_packets_snapshot,
                "total_duration_seconds": finding.total_duration_seconds_snapshot,
                "max_duration_seconds": finding.max_duration_seconds_snapshot,
                "avg_duration_seconds": finding.avg_duration_seconds_snapshot,
                "reputation_verdict": finding.reputation_verdict_snapshot,
                "reputation_score": finding.reputation_score_snapshot,
                "reputation_results": finding.reputation_results_snapshot,
                "risk_profile_id": finding.risk_profile_id,
                "risk_name": finding.risk_name_snapshot,
                "risk_activity": finding.risk_activity_snapshot,
                "risk_indicator_id": finding.risk_indicator_id,
                "ioc": finding.ioc_snapshot,
                "severity": finding.severity,
                "impact": finding.impact_snapshot,
                "recommendation": finding.recommendation_snapshot,
                "note": finding.note,
            }
            for finding in obj.findings.all()
        ]


class BulletinIPInputSerializer(serializers.Serializer):
    ip_address = serializers.IPAddressField(protocol="IPv4")
    role = serializers.ChoiceField(choices=BulletinIPRole.choices)
    port = serializers.IntegerField(required=False, allow_null=True, min_value=0, max_value=65535)
    note = serializers.CharField(required=False, allow_blank=True, max_length=255)


class BulletinCreateInputSerializer(serializers.Serializer):
    structure_id = serializers.PrimaryKeyRelatedField(queryset=Structure.objects.filter(is_active=True), source="structure")
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
    activity_ids = serializers.PrimaryKeyRelatedField(
        queryset=ActivityCatalog.objects.filter(is_active=True),
        source="activities",
        many=True,
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

    def validate_activities(self, value):
        if not value:
            raise serializers.ValidationError("Au moins une activité doit être liée au bulletin.")
        return value

class BulletinFromFindingsInputSerializer(serializers.Serializer):
    structure_id = serializers.PrimaryKeyRelatedField(queryset=Structure.objects.filter(is_active=True), source="structure")
    external_reference = serializers.CharField(required=False, allow_blank=True, max_length=128)
    severity = serializers.ChoiceField(choices=Bulletin._meta.get_field("severity").choices, required=False)
    status = serializers.ChoiceField(choices=Bulletin._meta.get_field("status").choices, required=False)
    sent_at = serializers.DateTimeField(required=False, allow_null=True)
    peer_observation_ids = serializers.PrimaryKeyRelatedField(
        queryset=PeerObservation.objects.select_related("network", "network__structure"),
        source="peer_observations",
        many=True,
        required=False,
    )
    peer_ips = serializers.ListField(
        child=serializers.IPAddressField(protocol="IPv4"),
        required=False,
        allow_empty=False,
        write_only=True,
    )
    risk_profile_ids = serializers.PrimaryKeyRelatedField(
        queryset=RiskProfile.objects.filter(is_active=True).select_related("activity").prefetch_related("port_services"),
        source="risk_profiles",
        many=True,
    )
    force_duplicate = serializers.BooleanField(required=False, default=False)

    def validate_peer_observation_ids(self, value):
        return value

    def validate_risk_profile_ids(self, value):
        if not value:
            raise serializers.ValidationError("Au moins un profil de risque doit être renseigné.")
        return value

    def validate(self, attrs):
        structure = attrs["structure"]
        observations = list(attrs.get("peer_observations", []))
        peer_ips = attrs.pop("peer_ips", [])
        if peer_ips:
            observations.extend(
                PeerObservation.objects.select_related("network", "network__structure", "peer_reputation")
                .filter(
                    network__structure=structure,
                    peer_reputation__ip_address__in=peer_ips,
                )
                .distinct()
            )
        observations = list({observation.id: observation for observation in observations}.values())
        if not observations:
            raise serializers.ValidationError({
                "peer_ips": "Aucune observation synchronisée ne correspond aux peers sélectionnés."
            })
        attrs["peer_observations"] = observations

        invalid_structure = [
            observation.id for observation in observations if observation.network.structure_id != structure.id
        ]
        if invalid_structure:
            raise serializers.ValidationError(
                {"peer_observation_ids": "Toutes les observations doivent appartenir à la structure du bulletin."}
            )

        risk_profiles = attrs.get("risk_profiles", [])
        unmatched_observations = []
        for observation in observations:
            compatible = False
            for profile in risk_profiles:
                ports = {item.port for item in profile.port_services.all()}
                if not ports or observation.host_port in ports:
                    compatible = True
                    break
            if not compatible:
                unmatched_observations.append(observation.id)
        if unmatched_observations:
            raise serializers.ValidationError({
                "risk_profile_ids": (
                    "Aucun risque sélectionné n’est compatible avec le port hôte des observations : "
                    + ", ".join(str(item) for item in unmatched_observations)
                )
            })

        return attrs


class BulletinAssistantMatchInputSerializer(serializers.Serializer):
    peer_ip = serializers.IPAddressField(protocol="IPv4")
    host_port = serializers.IntegerField(min_value=0, max_value=65535)
    indicator_id = serializers.PrimaryKeyRelatedField(
        queryset=RiskIndicator.objects.filter(is_active=True),
        source="risk_indicator",
    )
    structure_id = serializers.PrimaryKeyRelatedField(
        queryset=Structure.objects.filter(is_active=True),
        source="structure",
        required=False,
    )


class BulletinAssistantDraftInputSerializer(BulletinAssistantMatchInputSerializer):
    risk_profile_id = serializers.PrimaryKeyRelatedField(
        queryset=RiskProfile.objects.filter(is_active=True),
        source="risk_profile",
        required=False,
    )
    external_reference = serializers.CharField(required=False, allow_blank=True, max_length=128)
    force_duplicate = serializers.BooleanField(required=False, default=False)

    def validate(self, attrs):
        peer_ip = attrs["peer_ip"]
        host_port = attrs["host_port"]
        indicator = attrs["risk_indicator"]
        structure = attrs.get("structure")

        observations = PeerObservation.objects.select_related(
            "network", "network__structure", "peer_reputation"
        ).filter(peer_reputation__ip_address=peer_ip, host_port=host_port)
        if structure:
            observations = observations.filter(network__structure=structure)
        observations = list(observations)
        if not observations:
            raise serializers.ValidationError(
                {"peer_ip": "Aucune observation ne correspond à cette peer IP et à ce port hôte."}
            )

        structure_ids = {item.network.structure_id for item in observations}
        if not structure and len(structure_ids) > 1:
            raise serializers.ValidationError(
                {"structure_id": "Cette sélection existe dans plusieurs structures. Choisissez la structure."}
            )
        if not structure:
            structure = observations[0].network.structure

        profiles = RiskProfile.objects.filter(
            is_active=True,
            port_services__port=host_port,
            indicator_links__indicator=indicator,
        ).distinct()
        selected_profile = attrs.get("risk_profile")
        if selected_profile and not profiles.filter(pk=selected_profile.pk).exists():
            raise serializers.ValidationError(
                {"risk_profile_id": "Ce profil n'est pas associé au port et à l'IOC sélectionnés."}
            )
        if not selected_profile:
            profile_ids = list(profiles.values_list("id", flat=True))
            if not profile_ids:
                raise serializers.ValidationError(
                    {"indicator_id": "Aucun profil de risque ne correspond à ce port et à cet IOC."}
                )
            if len(profile_ids) > 1:
                raise serializers.ValidationError(
                    {"risk_profile_id": "Plusieurs risques correspondent. Choisissez le profil de risque."}
                )
            selected_profile = profiles.get(pk=profile_ids[0])

        attrs["structure"] = structure
        attrs["peer_observations"] = observations
        attrs["risk_profiles"] = [selected_profile]
        attrs.pop("risk_profile", None)
        attrs.pop("peer_ip", None)
        attrs.pop("host_port", None)
        return attrs
