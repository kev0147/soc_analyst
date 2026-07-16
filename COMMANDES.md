# Commandes utiles — SOC Analyst

Les commandes ci-dessous sont prévues pour **PowerShell sous Windows** et doivent être exécutées depuis la racine du projet.

```powershell
Set-Location K:\codes\ANALYST
```

## 1. Installation initiale

Créer l'environnement virtuel Python :

```powershell
py -m venv .venv
```

Installer les dépendances backend :

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

Installer les dépendances frontend :

```powershell
Set-Location frontend
npm ci
Set-Location ..
```

## 2. Configuration `.env`

Créer le fichier local à partir du modèle :

```powershell
Copy-Item backend\.env.example backend\.env
```

Générer une clé secrète Django :

```powershell
.\.venv\Scripts\python.exe -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Reporter la clé obtenue dans `backend\.env`, puis renseigner notamment :

```dotenv
DJANGO_SECRET_KEY=remplacer-par-une-cle-secrete
DJANGO_DEBUG=true
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
DJANGO_TIME_ZONE=Europe/London
CORS_ALLOWED_ORIGINS=http://localhost:4200,http://127.0.0.1:4200
CSRF_TRUSTED_ORIGINS=http://localhost:4200,http://127.0.0.1:4200

ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
IP_REPUTATION_TIMEOUT_SECONDS=20
IP_REPUTATION_ABUSEIPDB_TTL_HOURS=24
IP_REPUTATION_VIRUSTOTAL_TTL_HOURS=168
IP_REPUTATION_ERROR_RETRY_HOURS=1
BACKGROUND_JOBS_POLL_SECONDS=1
WORKER_HEARTBEAT_SECONDS=5
WORKER_STALE_SECONDS=20
SQLITE_TIMEOUT_SECONDS=30
```

Ne jamais ajouter `backend\.env` à Git.

## 3. Préparation de la base

Voir les migrations :

```powershell
.\.venv\Scripts\python.exe backend\manage.py showmigrations
```

Afficher le plan sans l'exécuter :

```powershell
.\.venv\Scripts\python.exe backend\manage.py migrate --plan
```

Appliquer les migrations :

```powershell
.\.venv\Scripts\python.exe backend\manage.py migrate
```

Créer une migration après une modification des modèles :

```powershell
.\.venv\Scripts\python.exe backend\manage.py makemigrations analyst
.\.venv\Scripts\python.exe backend\manage.py migrate
```

Vérifier qu'aucune migration ne manque :

```powershell
.\.venv\Scripts\python.exe backend\manage.py makemigrations --check --dry-run
.\.venv\Scripts\python.exe backend\manage.py migrate --check
```

## 4. Premier administrateur

Créer le premier administrateur :

```powershell
.\.venv\Scripts\python.exe backend\manage.py init_admin --email "soc@local.test" --password "REMPLACER-PAR-UN-MOT-DE-PASSE-FORT"
```

Avec un nom affiché facultatif :

```powershell
.\.venv\Scripts\python.exe backend\manage.py init_admin --email "soc@local.test" --password "REMPLACER-PAR-UN-MOT-DE-PASSE-FORT" --display-name "SOC"
```

Réinitialiser le mot de passe d'un utilisateur existant :

```powershell
.\.venv\Scripts\python.exe backend\manage.py changepassword "soc@local.test"
```

L'option `--force` de `init_admin` ne doit être utilisée que pour créer ou promouvoir explicitement un autre administrateur.

## 5. Démarrage quotidien

### Lanceur automatique

Sous Windows, double-cliquer sur `START_ANALYST.bat` lance les migrations, l'API,
le worker et le frontend, puis ouvre le navigateur. Les journaux sont enregistrés
dans `backend\.runtime`.

Pour arrêter uniquement les processus démarrés par ce lanceur, double-cliquer sur
`STOP_ANALYST.bat`.

Le démarrage manuel reste disponible ci-dessous pour le diagnostic.

Ouvrir trois terminaux depuis la racine du projet.

### Terminal 1 — API Django

```powershell
.\.venv\Scripts\python.exe backend\manage.py runserver 127.0.0.1:8000
```

### Terminal 2 — worker des traitements longs

```powershell
.\.venv\Scripts\python.exe backend\manage.py run_background_jobs
```

Le worker traite les imports CSV et les analyses IP. Les jobs restent en file dans SQLite lorsqu'il est arrêté.

Traiter uniquement la file actuelle puis arrêter le worker :

```powershell
.\.venv\Scripts\python.exe backend\manage.py run_background_jobs --once
```

Changer temporairement la fréquence de lecture de la file :

```powershell
.\.venv\Scripts\python.exe backend\manage.py run_background_jobs --poll-seconds 2
```

### Terminal 3 — Angular

```powershell
Set-Location frontend
npm start
```

Accès local :

- frontend : `http://localhost:4200`
- API : `http://127.0.0.1:8000/api/v1/`
- administration Django : `http://127.0.0.1:8000/admin/`

Arrêter un serveur ou le worker : `Ctrl+C` dans son terminal.

## 6. Vérifications et tests

Vérifier la configuration Django :

```powershell
.\.venv\Scripts\python.exe backend\manage.py check
```

Vérifier les dépendances Python :

```powershell
.\.venv\Scripts\python.exe -m pip check
```

Lancer tous les tests backend :

```powershell
.\.venv\Scripts\python.exe backend\manage.py test analyst
```

Lancer un test ou une classe précise :

```powershell
.\.venv\Scripts\python.exe backend\manage.py test analyst.tests.BackgroundJobTests
```

Compiler Angular :

```powershell
Set-Location frontend
npm run build
Set-Location ..
```

Lancer les tests frontend :

```powershell
Set-Location frontend
npm test
Set-Location ..
```

Vérification complète habituelle :

```powershell
.\.venv\Scripts\python.exe backend\manage.py check
.\.venv\Scripts\python.exe backend\manage.py makemigrations --check --dry-run
.\.venv\Scripts\python.exe backend\manage.py test analyst
Set-Location frontend
npm run build
Set-Location ..
```

## 7. Analyse de réputation en ligne de commande

Le fonctionnement normal passe par l'interface et le worker. Ces commandes directes sont surtout utiles pour le diagnostic.

Analyser les IP externes de tous les flows :

```powershell
.\.venv\Scripts\python.exe backend\manage.py run_ip_reputation --scope all_flows --limit 50 --tools abuseipdb,virustotal
```

Analyser les IP d'un import précis :

```powershell
.\.venv\Scripts\python.exe backend\manage.py run_ip_reputation --scope import --import-id 12 --limit 50 --tools abuseipdb,virustotal
```

Utiliser une seule plateforme :

```powershell
.\.venv\Scripts\python.exe backend\manage.py run_ip_reputation --scope all_flows --limit 50 --tools abuseipdb
```

Forcer exceptionnellement l'actualisation des résultats encore frais :

```powershell
.\.venv\Scripts\python.exe backend\manage.py run_ip_reputation --scope all_flows --limit 50 --tools abuseipdb,virustotal --force-refresh
```

## 8. Reprise de données historiques

Importer un ancien cache de réputation depuis SQLite ou CSV :

```powershell
.\.venv\Scripts\python.exe backend\manage.py import_legacy_ip_reputation "C:\chemin\ancien-cache.sqlite"
```

Ou :

```powershell
.\.venv\Scripts\python.exe backend\manage.py import_legacy_ip_reputation "C:\chemin\reputations.csv"
```

Une commande d'import historique de bulletins existe également. Ne l'utiliser qu'après validation du format et sur une sauvegarde de la base :

```powershell
.\.venv\Scripts\python.exe backend\manage.py import_bulletins_excel "C:\chemin\anciens-bulletins.xlsx" --user-email "soc@local.test" --default-structure-code "STRUCTURE"
```

Afficher l'aide exacte d'une commande :

```powershell
.\.venv\Scripts\python.exe backend\manage.py help
.\.venv\Scripts\python.exe backend\manage.py run_background_jobs --help
.\.venv\Scripts\python.exe backend\manage.py run_ip_reputation --help
```

## 9. Sauvegarde SQLite et médias

Arrêter de préférence l'API et le worker avant une copie manuelle de SQLite.

Créer le dossier de sauvegarde et copier la base :

```powershell
New-Item -ItemType Directory -Path backups -Force
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
Copy-Item backend\db.sqlite3 "backups\db-$stamp.sqlite3"
```

Sauvegarder les fichiers importés et rapports de rejet :

```powershell
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
Compress-Archive -Path backend\media\* -DestinationPath "backups\media-$stamp.zip"
```

Vérifier l'intégrité de la base :

```powershell
.\.venv\Scripts\python.exe -c "import sqlite3; db=sqlite3.connect(r'backend\db.sqlite3'); print(db.execute('PRAGMA integrity_check').fetchone()[0]); db.close()"
```

Une restauration remplace les données courantes. Arrêter l'API et le worker, conserver une copie de la base actuelle, puis seulement recopier la sauvegarde choisie.

## 10. Console Django

Ouvrir la console avec les modèles automatiquement importés :

```powershell
.\.venv\Scripts\python.exe backend\manage.py shell
```

Afficher quelques compteurs sans ouvrir la console interactive :

```powershell
.\.venv\Scripts\python.exe backend\manage.py shell -c "from analyst.models import Flow, FlowImport, BackgroundJob; print({'flows': Flow.objects.count(), 'imports': FlowImport.objects.count(), 'jobs': BackgroundJob.objects.count()})"
```

## 11. Git

Voir l'état du dépôt :

```powershell
git status
git diff
git diff --check
```

Préparer et enregistrer les modifications :

```powershell
git add .
git status
git commit -m "Décrire clairement la modification"
```

Récupérer les changements distants avant de pousser :

```powershell
git fetch origin
git pull --rebase origin main
git push origin main
```

En cas de conflit pendant le rebase : corriger les fichiers, puis exécuter :

```powershell
git add .
git rebase --continue
```

Pour abandonner uniquement le rebase en cours :

```powershell
git rebase --abort
```

Voir les derniers commits :

```powershell
git log --oneline --decorate -10
```

Les fichiers `.env`, `*.sqlite3`, `media`, `media_test`, `__pycache__` et `*.pyc` ne doivent pas être ajoutés au dépôt.

## 12. Diagnostic local

Voir les processus Python :

```powershell
Get-Process python -ErrorAction SilentlyContinue | Select-Object Id, StartTime, Path
```

Voir quel processus écoute sur les ports du projet :

```powershell
Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
Get-NetTCPConnection -LocalPort 4200 -ErrorAction SilentlyContinue
```

Tester si l'API répond :

```powershell
Invoke-WebRequest http://127.0.0.1:8000/api/v1/auth/me/ -UseBasicParsing
```

Une réponse `403` sur cette dernière commande signifie généralement que l'API répond mais que la requête PowerShell ne possède pas de session authentifiée.
