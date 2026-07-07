from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import (
    AuditEvent,
    Bulletin,
    BulletinTypeCatalog,
    Flow,
    FlowImport,
    Network,
    NetworkCIDR,
    RecommendationCatalog,
    RiskCatalog,
    Structure,
    User,
)


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    ordering = ("email",)
    list_display = ("email", "display_name", "role", "is_active")
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Profil", {"fields": ("display_name", "role")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Dates", {"fields": ("last_login", "date_joined", "updated_at")}),
    )
    add_fieldsets = ((None, {"fields": ("email", "password1", "password2", "role")}),)
    readonly_fields = ("last_login", "date_joined", "updated_at")


admin.site.register(Structure)
admin.site.register(Network)
admin.site.register(NetworkCIDR)
admin.site.register(FlowImport)
admin.site.register(Flow)
admin.site.register(Bulletin)
admin.site.register(BulletinTypeCatalog)
admin.site.register(RiskCatalog)
admin.site.register(RecommendationCatalog)
admin.site.register(AuditEvent)
