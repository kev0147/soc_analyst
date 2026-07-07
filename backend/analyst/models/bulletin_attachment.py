from django.db import models


class BulletinAttachment(models.Model):
    response = models.ForeignKey("analyst.BulletinResponse", on_delete=models.CASCADE, related_name="attachments")
    original_filename = models.CharField(max_length=255)
    stored_path = models.CharField(max_length=1024)
    content_type = models.CharField(max_length=255, blank=True)
    file_size_bytes = models.PositiveBigIntegerField()
    file_sha256 = models.CharField(max_length=64)
    uploaded_at = models.DateTimeField(auto_now_add=True)

