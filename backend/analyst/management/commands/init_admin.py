from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from analyst.models.choices import UserRole


class Command(BaseCommand):
    help = "Crée le premier administrateur de l'application Analyst."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True, help="Adresse email de l'administrateur.")
        parser.add_argument("--password", required=True, help="Mot de passe initial.")
        parser.add_argument("--display-name", default="", help="Nom affiché.")
        parser.add_argument(
            "--force",
            action="store_true",
            help="Autorise la création/promotion même si un administrateur existe déjà.",
        )

    def handle(self, *args, **options):
        User = get_user_model()
        email = User.objects.normalize_email(options["email"]).lower()
        password = options["password"]
        display_name = options["display_name"]
        force = options["force"]

        admin_exists = User.objects.filter(role=UserRole.ADMIN, is_active=True).exists()
        if admin_exists and not force:
            raise CommandError("Un administrateur actif existe déjà. Utilisez --force pour forcer.")

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "display_name": display_name,
                "role": UserRole.ADMIN,
                "is_staff": True,
                "is_superuser": True,
            },
        )
        if not created:
            user.display_name = display_name or user.display_name
            user.role = UserRole.ADMIN
            user.is_staff = True
            user.is_superuser = True

        user.set_password(password)
        user.save()

        action = "créé" if created else "mis à jour"
        self.stdout.write(self.style.SUCCESS(f"Administrateur {action} : {user.email}"))
