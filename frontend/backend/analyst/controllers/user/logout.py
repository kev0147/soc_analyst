from django.contrib.auth import logout
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit


class LogoutController(APIView):
    def post(self, request):
        record_audit(request, "AUTH_LOGOUT", request.user)
        logout(request)
        return Response(status=204)

