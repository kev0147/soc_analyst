from django.db import migrations


SOURCE_KEY = "system-default-unclassified-risk"


def create_default_profile(apps, schema_editor):
    ActivityCatalog = apps.get_model("analyst", "ActivityCatalog")
    RiskProfile = apps.get_model("analyst", "RiskProfile")
    activity, _ = ActivityCatalog.objects.get_or_create(
        name="Activité à qualifier",
        defaults={
            "description": "Activité utilisée lorsqu’aucun profil spécialisé ne couvre les ports observés.",
            "is_active": True,
        },
    )
    RiskProfile.objects.update_or_create(
        source_key=SOURCE_KEY,
        defaults={
            "activity": activity,
            "name": "Risque à qualifier",
            "impact": "Communication externe nécessitant une qualification complémentaire par le SOC.",
            "recommendation": "Analyser la légitimité de la communication, identifier le service concerné et appliquer les mesures adaptées.",
            "default_severity": "medium",
            "is_active": True,
        },
    )


def remove_default_profile(apps, schema_editor):
    RiskProfile = apps.get_model("analyst", "RiskProfile")
    RiskProfile.objects.filter(source_key=SOURCE_KEY).delete()


class Migration(migrations.Migration):
    dependencies = [("analyst", "0018_reputationsourcestate")]
    operations = [
        migrations.RunPython(create_default_profile, remove_default_profile),
    ]
