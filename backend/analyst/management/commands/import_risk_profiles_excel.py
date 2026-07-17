from django.core.management.base import BaseCommand, CommandError

from analyst.services.risk_profiles import import_risk_profiles_catalog


class Command(BaseCommand):
    help = "Importe le catalogue ACTIVITÉS/PORTS/RISQUES/IMPACTS/IOCS/RECOMMANDATIONS/CRITICITÉ."

    def add_arguments(self, parser):
        parser.add_argument("path", help="Chemin du fichier .xlsx ou .csv.")
        parser.add_argument("--sheet-index", type=int, default=1, help="Numéro de feuille Excel (défaut : 1).")
        parser.add_argument("--dry-run", action="store_true", help="Valide le fichier sans conserver les données.")

    def handle(self, *args, **options):
        try:
            result = import_risk_profiles_catalog(
                options["path"],
                sheet_index=options["sheet_index"],
                dry_run=options["dry_run"],
            )
        except (FileNotFoundError, ValueError) as exc:
            raise CommandError(str(exc)) from exc

        mode = "Simulation" if result["dry_run"] else "Import"
        self.stdout.write(self.style.SUCCESS(
            f"{mode} terminé : {result['created']} créé(s), {result['updated']} mis à jour, "
            f"{len(result['rejected'])} rejet(s)."
        ))
        for item in result["rejected"][:50]:
            self.stdout.write(self.style.WARNING(f"- Ligne {item['row']}: {item['reason']}"))
