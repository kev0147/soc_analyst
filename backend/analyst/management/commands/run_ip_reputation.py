from django.core.management.base import BaseCommand, CommandError

from analyst.models.choices import ReputationSource
from analyst.services.ip_reputation import run_reputation_analysis


class Command(BaseCommand):
    help = "Lance une analyse de réputation IP sur les IP externes observées dans les flows."

    def add_arguments(self, parser):
        parser.add_argument("--scope", choices=("all_flows", "import"), default="all_flows")
        parser.add_argument("--import-id", type=int, default=None)
        parser.add_argument("--limit", type=int, default=50)
        parser.add_argument(
            "--tools",
            default="abuseipdb,virustotal",
            help="Liste séparée par virgule : abuseipdb,virustotal",
        )
        parser.add_argument(
            "--force-refresh",
            action="store_true",
            help="Réanalyse également les résultats encore frais.",
        )

    def handle(self, *args, **options):
        tools = [item.strip() for item in options["tools"].split(",") if item.strip()]
        invalid = sorted(set(tools) - {ReputationSource.ABUSEIPDB, ReputationSource.VIRUSTOTAL})
        if invalid:
            raise CommandError(f"Outils invalides : {', '.join(invalid)}")

        try:
            result = run_reputation_analysis(
                scope=options["scope"],
                import_id=options["import_id"],
                tools=tools,
                limit=options["limit"],
                force_refresh=options["force_refresh"],
            )
        except Exception as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"Analyse terminée : {result['analyzed_count']} IP analysées sur {result['candidate_count']} candidates."
            )
        )
