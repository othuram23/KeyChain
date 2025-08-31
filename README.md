# KeyChain

KeyChain — gestionnaire sécurisé de mots de passe et boîte à outils pour évaluer/générer/stocker des secrets localement.

## But

Fournir un coffre-fort local chiffré, des utilitaires de génération et d'évaluation de mots de passe, et des composants faciles à auditer et à intégrer.

## Où commencer

- Documentation complète : dossier `docs/`.
- Script d'initialisation : `scripts/setup_repo.sh` (si présent).

## Quickstart (dev)

1. Créez un environnement Python (recommandé) :

   python -m venv .venv
   .\.venv\Scripts\activate

2. Installez les dépendances (si `AppGenPP/app/requirements.txt` existe) :

   pip install -r AppGenPP/app/requirements.txt

3. Installez les hooks `pre-commit` et lancez un premier lint/test :

   pip install pre-commit
   pre-commit install
   pre-commit run --all-files

4. Lancer les tests unitaires (si pytest est installé) :

   pytest -q

5. Exécuter l'application (prototype) :

   python AppGenPP/app/main.py

## CI / sécurité

Le dépôt contient des modèles (à compléter) pour :

- GitHub Actions (`.github/workflows/`) : lint → tests → SAST
- Pré-commit hooks (`.pre-commit-config.yaml`) pour formatter et détecter secrets

## Contribuer

Voir `CONTRIBUTING.md` pour le guide de contribution, la checklist PR et les règles d'écriture de code.

## Licence

Voir le fichier `LICENSE` à la racine du projet.

## Contacts

Pour les questions générales : ouvre une issue sur GitHub. Pour les rapports de sécurité, consulte `SECURITY.md`.
