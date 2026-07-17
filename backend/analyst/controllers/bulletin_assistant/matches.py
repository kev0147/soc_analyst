from django.db.models import Prefetch
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.models import PeerObservation, RiskProfile, RiskProfileIndicator
from analyst.serializers import PeerObservationSerializer, RiskProfileSerializer
from analyst.serializers.bulletin.serializer import BulletinAssistantMatchInputSerializer


class BulletinAssistantMatchesController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def get(self, request):
        serializer = BulletinAssistantMatchInputSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        structure = data.get("structure")
        indicator = data["risk_indicator"]

        observations = PeerObservation.objects.select_related(
            "network", "network__structure", "peer_reputation"
        ).filter(
            peer_reputation__ip_address=data["peer_ip"],
            host_port=data["host_port"],
        )
        if structure:
            observations = observations.filter(network__structure=structure)

        profiles = RiskProfile.objects.filter(
            is_active=True,
            port_services__port=data["host_port"],
            indicator_links__indicator=indicator,
        ).prefetch_related(
            "port_services",
            Prefetch(
                "indicator_links",
                queryset=RiskProfileIndicator.objects.select_related("indicator"),
            ),
        ).distinct()

        structure_ids = set(observations.values_list("network__structure_id", flat=True))
        return Response({
            "selection": {
                "peer_ip": data["peer_ip"],
                "host_port": data["host_port"],
                "indicator": {"id": indicator.id, "name": indicator.name},
                "structure_id": structure.id if structure else None,
            },
            "observations": PeerObservationSerializer(observations, many=True).data,
            "risk_profiles": RiskProfileSerializer(profiles, many=True).data,
            "requires_structure_choice": not structure and len(structure_ids) > 1,
            "requires_risk_choice": profiles.count() > 1,
            "can_create_draft": bool(observations.exists() and profiles.exists() and (structure or len(structure_ids) == 1)),
        })
