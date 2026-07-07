from rest_framework.response import Response
from rest_framework.views import APIView

from analyst.serializers import UserSerializer


class CurrentUserController(APIView):
    def get(self, request):
        return Response(UserSerializer(request.user).data)

