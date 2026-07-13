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
            default="abuseipdb,virustotal,shodan",
            help="Liste séparée par virgule : abuseipdb,virustotal,shodan",
        )

    def handle(self, *args, **options):
        tools = [item.strip() for item in options["tools"].split(",") if item.strip()]
        invalid = sorted(set(tools) - set(ReputationSource.values))
        if invalid:
            raise CommandError(f"Outils invalides : {', '.join(invalid)}")

        try:
            result = run_reputation_analysis(
                scope=options["scope"],
                import_id=options["import_id"],
                tools=tools,
                limit=options["limit"],
            )
        except Exception as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"Analyse terminée : {result['analyzed_count']} IP analysées sur {result['candidate_count']} candidates."
            )
        )
