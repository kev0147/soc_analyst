from django.db import models


class FlowImportItem(models.Model):
    flow_import = models.ForeignKey("analyst.FlowImport", on_delete=models.CASCADE, related_name="items")
    flow = models.ForeignKey("analyst.Flow", on_delete=models.CASCADE, related_name="import_items")
    source_row_number = models.PositiveBigIntegerField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("flow_import", "flow"), name="uniq_flow_per_import")
        ]

