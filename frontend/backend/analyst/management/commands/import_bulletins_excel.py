from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from analyst.services.bulletins.excel_importer import import_bulletins_from_excel


class Command(BaseCommand):
    help = "Importe des bulletins depuis un fichier Excel .xlsx ou CSV."

    def add_arguments(self, parser):
        parser.add_argument("path", help="Chemin vers le fichier .xlsx ou .csv.")
        parser.add_argument("--user-email", required=True, help="Utilisateur créateur des bulletins.")
        parser.add_argument("--default-structure-code", default="", help="Structure par défaut si la colonne est absente.")
        parser.add_argument("--force-duplicates", action="store_true", help="Créer même si un doublon exact est détecté.")

    def handle(self, *args, **options):
        User = get_user_model()
        try:
            user = User.objects.get(email=options["user_email"].lower())
        except User.DoesNotExist as exc:
            raise CommandError("Utilisateur introuvable.") from exc

        result = import_bulletins_from_excel(
            options["path"],
            user=user,
            default_structure_code=options["default_structure_code"] or None,
            force_duplicates=options["force_duplicates"],
        )
        self.stdout.write(self.style.SUCCESS(f"Bulletins créés : {result['created']} / groupes : {result['group_count']}"))
        if result["rejected"]:
            self.stdout.write(self.style.WARNING(f"Rejets : {len(result['rejected'])}"))
            for item in result["rejected"][:20]:
                self.stdout.write(f"- {item['reference']}: {item['reason']}")
