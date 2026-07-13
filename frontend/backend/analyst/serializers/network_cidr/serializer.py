from rest_framework import serializers

from analyst.models import NetworkCIDR


class NetworkCIDRSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkCIDR
        fields = "__all__"
        read_only_fields = ("created_at",)

    def validate(self, attrs):
        instance = self.instance or NetworkCIDR()
        for key, value in attrs.items():
            setattr(instance, key, value)
        instance.clean()
        attrs["cidr"] = instance.cidr
        return attrs

