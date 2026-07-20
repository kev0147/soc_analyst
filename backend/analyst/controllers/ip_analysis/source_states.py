from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.models import ReputationSourceState
from analyst.models.choices import ReputationSource


class IPAnalysisSourceStatesController(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        states = {item.source: item for item in ReputationSourceState.objects.all()}
        now = timezone.now()
        results = []
        for source in (ReputationSource.ABUSEIPDB, ReputationSource.VIRUSTOTAL):
            state = states.get(source)
            results.append({
                "source": source,
                "quota_exhausted": bool(
                    state
                    and state.quota_exhausted_until
                    and state.quota_exhausted_until > now
                ),
                "quota_exhausted_until": state.quota_exhausted_until if state else None,
                "last_http_status": state.last_http_status if state else None,
                "last_error_message": state.last_error_message if state else "",
            })
        return Response({"results": results})
