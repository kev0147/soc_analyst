from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdminOrAnalyst
from analyst.services.ip_reputation import candidate_ips


class IPAnalysisCandidatesController(APIView):
    permission_classes = (IsAdminOrAnalyst,)

    def get(self, request):
        serializer = serializers.Serializer()
        try:
            limit = int(request.query_params.get("limit", 50))
            candidates = candidate_ips(
                scope=request.query_params.get("scope", "all_flows"),
                import_id=int(request.query_params["import_id"]) if request.query_params.get("import_id") else None,
                limit=limit,
                tools=request.query_params.getlist("tools") or None,
                force_refresh=request.query_params.get("force_refresh", "").lower() in {"1", "true", "yes"},
            )
        except (ValueError, TypeError) as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        record_audit(request, "IP_REPUTATION_CANDIDATES_VIEWED", details={"count": len(candidates)})
        return Response(
            {
                "results": [
                    {
                        "ip_address": item.ip_address,
                        "flow_count": item.flow_count,
                        "first_seen_at": item.first_seen_at,
                        "last_seen_at": item.last_seen_at,
                        "analyzed_source_count": item.analyzed_source_count,
                        "priority": item.priority,
                        "missing_tools": item.missing_tools,
                        "expired_tools": item.expired_tools,
                        "fresh_tools": item.fresh_tools,
                        "due_tools": item.due_tools,
                    }
                    for item in candidates
                ]
            }
        )
