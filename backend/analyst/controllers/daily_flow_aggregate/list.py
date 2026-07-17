from django.utils.dateparse import parse_date
from rest_framework import generics
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated

from analyst.models import DailyFlowAggregate
from analyst.serializers import DailyFlowAggregateSerializer


class DailyFlowAggregateListController(generics.ListAPIView):
    serializer_class = DailyFlowAggregateSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        queryset = DailyFlowAggregate.objects.select_related("structure", "network")
        params = self.request.query_params
        if params.get("structure_id"):
            try:
                queryset = queryset.filter(structure_id=int(params["structure_id"]))
            except ValueError as exc:
                raise ValidationError({"structure_id": "Doit être un entier."}) from exc
        for name in ("peer_ip", "host_ip", "reputation_verdict"):
            if params.get(name):
                queryset = queryset.filter(**{name: params[name]})
        date_from = parse_date(params.get("date_from", ""))
        date_to = parse_date(params.get("date_to", ""))
        if date_from:
            queryset = queryset.filter(date__gte=date_from)
        if date_to:
            queryset = queryset.filter(date__lte=date_to)
        return queryset
