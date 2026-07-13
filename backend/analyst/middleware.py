from django.conf import settings
from django.http import HttpResponse


class LocalDevCORSMiddleware:
    """
    CORS minimal pour le MVP local Angular (:4200) -> Django (:8000).
    À remplacer par django-cors-headers si on industrialise le déploiement.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        origin = request.headers.get("Origin")
        allowed = getattr(settings, "LOCAL_DEV_CORS_ORIGINS", set())

        if request.method == "OPTIONS" and origin in allowed:
            response = HttpResponse(status=204)
        else:
            response = self.get_response(request)

        if origin in allowed:
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Credentials"] = "true"
            response["Access-Control-Allow-Headers"] = "Content-Type, X-CSRFToken, X-Requested-With"
            response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"

        return response
