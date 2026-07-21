from django.db.models import Q
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from analyst.models import Bulletin
from analyst.serializers import BulletinSerializer


class BulletinListController(generics.ListAPIView):
    serializer_class = BulletinSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = Bulletin.objects.filter(deleted_at__isnull=True).select_related("structure").prefetch_related(
            "ip_addresses",
            "risk_links__risk",
            "activity_links__activity",
            "recommendation_links__recommendation",
            "findings",
        )
        params = self.request.query_params
        search = (params.get("search") or "").strip()
        if search:
            queryset = queryset.filter(
                Q(reference__icontains=search)
                | Q(external_reference__icontains=search)
                | Q(ip_addresses__ip_address__icontains=search)
                | Q(findings__peer_ip_snapshot__icontains=search)
            )
        structure_id = params.get("structure_id")
        if structure_id:
            queryset = queryset.filter(structure_id=structure_id)
        status = params.get("status")
        if status:
            queryset = queryset.filter(status=status)
        severity = params.get("severity")
        if severity:
            queryset = queryset.filter(severity=severity)
        date_from = params.get("date_from")
        if date_from:
            queryset = queryset.filter(created_at__date__gte=date_from)
        date_to = params.get("date_to")
        if date_to:
            queryset = queryset.filter(created_at__date__lte=date_to)
        return queryset.distinct().order_by("-created_at")
