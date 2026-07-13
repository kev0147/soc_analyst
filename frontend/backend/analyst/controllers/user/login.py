from django.contrib.auth import login
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.controllers.audit import record_audit
from analyst.serializers.user import LoginSerializer, UserSerializer


class LoginController(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={"request": request})
        if not serializer.is_valid():
            record_audit(request, "AUTH_LOGIN_FAILURE", details={"email": request.data.get("email", "")})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = serializer.validated_data["user"]
        login(request, user)
        record_audit(request, "AUTH_LOGIN_SUCCESS", user)
        return Response(UserSerializer(user).data)

