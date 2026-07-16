from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.permissions import IsAdmin
from analyst.services.jobs.supervisor import worker_log_tail


class WorkerLogsController(APIView):
    permission_classes = (IsAdmin,)

    def get(self, request):
        return Response(worker_log_tail(request.query_params.get("lines", 100)))
