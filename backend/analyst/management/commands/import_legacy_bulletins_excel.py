from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from analyst.services.bulletins.legacy_excel_importer import import_legacy_bulletins_workbook


class Command(BaseCommand):
    help = "Importe les anciens bulletins en regroupant automatiquement les feuilles par ref_alerte."

    def add_arguments(self, parser):
        parser.add_argument("path", help="Chemin du classeur .xlsx historique.")
        parser.add_argument("--user-email", required=True, help="Compte créateur des bulletins importés.")
        parser.add_argument("--default-structure-code", default="", help="Structure utilisée si elle manque dans le classeur.")
        parser.add_argument("--force-duplicates", action="store_true")
        parser.add_argument("--dry-run", action="store_true", help="Valide sans conserver les données.")

    def handle(self, *args, **options):
        User = get_user_model()
        try:
            user = User.objects.get(email=options["user_email"].strip().lower())
        except User.DoesNotExist as exc:
            raise CommandError("Utilisateur introuvable.") from exc
        try:
            result = import_legacy_bulletins_workbook(
                options["path"],
                user=user,
                default_structure_code=options["default_structure_code"] or None,
                force_duplicates=options["force_duplicates"],
                dry_run=options["dry_run"],
            )
        except (FileNotFoundError, ValueError) as exc:
            raise CommandError(str(exc)) from exc

        mode = "Simulation" if result["dry_run"] else "Import"
        self.stdout.write(self.style.SUCCESS(
            f"{mode} terminé : {result['created']} bulletin(s), {result['duplicates']} doublon(s), "
            f"{len(result['rejected'])} rejet(s)."
        ))
        for item in result["rejected"][:50]:
            self.stdout.write(self.style.WARNING(f"- {item['reference']}: {item['reason']}"))
