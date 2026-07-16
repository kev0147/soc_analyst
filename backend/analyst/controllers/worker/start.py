from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.controllers.permissions import IsAdmin
from analyst.services.jobs.supervisor import start_background_worker


class WorkerStartController(APIView):
    permission_classes = (IsAdmin,)

    def post(self, request):
        try:
            result = start_background_worker()
        except OSError as exc:
            return Response(
                {"detail": f"Le processus worker n'a pas pu démarrer : {exc}"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        record_audit(request, "BACKGROUND_WORKER_START_REQUESTED", details=result)
        return Response(
            result,
            status=status.HTTP_200_OK if result.get("already_running") else status.HTTP_202_ACCEPTED,
        )
