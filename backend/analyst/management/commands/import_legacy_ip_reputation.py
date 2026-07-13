from django.core.management.base import BaseCommand

from analyst.services.ip_reputation.legacy_importer import import_legacy_reputation


class Command(BaseCommand):
    help = "Importe un ancien cache/résultat de réputation IP depuis SQLite ou CSV."

    def add_arguments(self, parser):
        parser.add_argument("path", help="Chemin vers le fichier .sqlite/.db ou .csv.")

    def handle(self, *args, **options):
        result = import_legacy_reputation(options["path"])
        self.stdout.write(
            self.style.SUCCESS(
                f"Réputation importée : {result['imported']} lignes, {result['skipped']} ignorées, {len(result['errors'])} erreurs."
            )
        )
        for item in result["errors"][:20]:
            self.stdout.write(self.style.WARNING(f"- ligne {item['row']}: {item['reason']}"))
