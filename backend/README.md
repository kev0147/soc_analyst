# Backend SOC Analyst

## Démarrage local

Le lanceur Windows `START_ANALYST.bat` situé à la racine démarre automatiquement
l'API, le worker et Angular. `STOP_ANALYST.bat` arrête les processus correspondants.

Depuis la racine du projet, ouvrir deux terminaux.

Serveur API :

```powershell
.\.venv\Scripts\python.exe backend\manage.py runserver
```

Worker des imports CSV et analyses IP :

```powershell
.\.venv\Scripts\python.exe backend\manage.py run_background_jobs
```

La file est persistée dans SQLite. Un job reste en attente si le worker est arrêté et sera traité à son prochain démarrage. Un seul worker doit être lancé avec SQLite ; un verrou local empêche un second démarrage accidentel.

Pour traiter la file actuelle puis arrêter le worker :

```powershell
.\.venv\Scripts\python.exe backend\manage.py run_background_jobs --once
```

## API des jobs

- `GET /api/v1/background-jobs/`
- `GET /api/v1/background-jobs/{id}/`
- `POST /api/v1/background-jobs/{id}/retry/`
- `GET /api/v1/workers/status/`
- `POST /api/v1/workers/start/` (administrateur)

## API d'analyse corrélée

- `GET /api/v1/analytics/malicious-communications/`

Le périmètre est choisi avec `scope=structure`, `scope=import` ou
`scope=date_range`. L'API agrège par hôte les peers malveillants, pays, ports,
volumes et durées.

La confirmation d'un import et le lancement d'une analyse IP répondent immédiatement avec un objet `job`. Le frontend interroge ensuite l'endpoint de détail jusqu'au statut `completed` ou `failed`.
