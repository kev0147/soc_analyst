from rest_framework import serializers

from analyst.models import Bulletin


class BulletinSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bulletin
        fields = "__all__"
        read_only_fields = (
            "reference_year", "sequence_number", "reference", "ip_signature",
            "created_by", "updated_by", "created_at", "updated_at", "deleted_at", "deleted_by",
        )

