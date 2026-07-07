from django.core.validators import RegexValidator
from django.db import models

from .base import TimestampedModel


class Structure(TimestampedModel):
    name = models.CharField(max_length=255, unique=True)
    code = models.CharField(
        max_length=32,
        unique=True,
        validators=[RegexValidator(r"^[A-Z0-9_-]+$", "Utilisez des majuscules, chiffres, _ ou -." )],
    )
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ("name",)

    def save(self, *args, **kwargs):
        self.code = self.code.strip().upper()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

