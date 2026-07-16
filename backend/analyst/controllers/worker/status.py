from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.services.jobs.supervisor import worker_status


class WorkerStatusController(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return Response(worker_status())
