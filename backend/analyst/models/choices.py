from django.db import models


class UserRole(models.TextChoices):
    ADMIN = "admin", "Administrateur"
    ANALYST = "analyst", "Analyste"
    VIEWER = "viewer", "Lecteur"


class ImportStatus(models.TextChoices):
    PENDING = "pending", "En attente"
    PROCESSING = "processing", "En cours"
    COMPLETED = "completed", "Terminé"
    COMPLETED_WITH_ERRORS = "completed_with_errors", "Terminé avec erreurs"
    FAILED = "failed", "Échoué"


class EndpointRole(models.TextChoices):
    CLIENT = "client", "Client"
    SERVER = "server", "Serveur"
    UNKNOWN = "unknown", "Inconnu"


class MappingMethod(models.TextChoices):
    ORIENTATION = "orientation", "Orientation CSV"
    SUBJECT_PEER_FALLBACK = "subject_peer_fallback", "Subject/Peer par défaut"


class FlowDirection(models.TextChoices):
    OUTBOUND = "outbound", "Sortant"
    INBOUND = "inbound", "Entrant"
    INTERNAL = "internal", "Interne"
    EXTERNAL = "external", "Externe"


class BulletinSeverity(models.TextChoices):
    LOW = "low", "Faible"
    MEDIUM = "medium", "Moyenne"
    HIGH = "high", "Élevée"
    CRITICAL = "critical", "Critique"


class BulletinStatus(models.TextChoices):
    DRAFT = "draft", "Brouillon"
    SENT = "sent", "Envoyé"
    ACKNOWLEDGED = "acknowledged", "Pris en compte"
    RESOLVED = "resolved", "Résolu"
    CLOSED = "closed", "Clôturé"


class BulletinIPRole(models.TextChoices):
    SOURCE = "source", "Source"
    DESTINATION = "destination", "Destination"


class ReputationSource(models.TextChoices):
    ABUSEIPDB = "abuseipdb", "AbuseIPDB"
    VIRUSTOTAL = "virustotal", "VirusTotal"
    SHODAN = "shodan", "Shodan"


class ReputationVerdict(models.TextChoices):
    MALICIOUS = "malicious", "Malveillant"
    SUSPICIOUS = "suspicious", "Suspect"
    CLEAN = "clean", "Propre"
    UNKNOWN = "unknown", "Inconnu"


class ReputationStatus(models.TextChoices):
    SUCCESS = "success", "Succès"
    SKIPPED = "skipped", "Ignoré"
    ERROR = "error", "Erreur"
