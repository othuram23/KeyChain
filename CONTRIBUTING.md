# Contribuer à KeyChain

Merci de vouloir contribuer ! Ce document décrit le flux de contribution, la checklist PR, les bonnes pratiques et comment exécuter les tests locaux.

## Flux minimal

1. Fork du dépôt.
2. Créez une branche descriptive (ex : `feat/password-generator`, `fix/typo-readme`).
3. Écrivez des tests pour tout nouveau comportement.
4. Lancez les hooks locaux : `pre-commit run --all-files`.
5. Ouvrez une Pull Request ciblant `main` (ou la branche indiquée dans la contribution).

## Style de code

- Python : suivez `black` + `flake8`.
- Gardez des fonctions petites et testables.
- Ajoutez des docstrings et commentez les décisions non triviales.

## Tests

- Les tests sont exécutés avec `pytest` dans `AppGenPP/app/tests/`.
- Exemple :

  python -m venv .venv
  .\.venv\Scripts\activate
  pip install -r AppGenPP/app/requirements.txt
  pip install -r AppGenPP/app/tests/requirements.txt || true
  pytest -q

## Checklist PR

- [ ] La branche suit le pattern `feat/` `fix/` `docs/` ou `chore/`.
- [ ] Les tests passent localement.
- [ ] Les hooks `pre-commit` ont été exécutés.
- [ ] Une description claire du changement est fournie.
- [ ] Au moins une review demandée.

## Sécurité et divulgation

Ne commitez jamais de secrets. Utilisez `git-secrets` ou `pre-commit` pour détecter les clés accidentelles.
Si vous découvrez une vulnérabilité, suivez `SECURITY.md`.

## Merci

Votre contribution rend KeyChain meilleur pour tout le monde. ❤️
