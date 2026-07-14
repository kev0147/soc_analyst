from django.db import migrations, models
import django.db.models.deletion


def copy_import_structures(apps, schema_editor):
    FlowImport = apps.get_model("analyst", "FlowImport")
    for flow_import in FlowImport.objects.select_related("network__structure").all().iterator():
        flow_import.structure_id = flow_import.network.structure_id
        flow_import.save(update_fields=("structure",))


class Migration(migrations.Migration):

    dependencies = [
        ("analyst", "0005_peerobservation_avg_duration_seconds_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="flowimport",
            name="structure",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="flow_imports",
                to="analyst.structure",
            ),
        ),
        migrations.RunPython(copy_import_structures, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="flowimport",
            name="structure",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="flow_imports",
                to="analyst.structure",
            ),
        ),
        migrations.AlterField(
            model_name="flowimport",
            name="network",
            field=models.ForeignKey(
                blank=True,
                help_text="Ancien rattachement mono-réseau, conservé uniquement pour l'historique.",
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="imports",
                to="analyst.network",
            ),
        ),
        migrations.AddIndex(
            model_name="flowimport",
            index=models.Index(fields=["structure", "uploaded_at"], name="analyst_flo_structu_fb8d5e_idx"),
        ),
        migrations.RemoveIndex(
            model_name="bulletin",
            name="analyst_bul_network_b40dcc_idx",
        ),
        migrations.RemoveField(
            model_name="bulletin",
            name="network",
        ),
    ]
