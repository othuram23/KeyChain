# Keychain – Gestionnaire de mots de passe sécurisé

---

## Description

**Keychain** est un gestionnaire de mots de passe complet et sécurisé écrit en Python. Il propose des fonctionnalités avancées pour générer, évaluer, chiffrer, stocker et gérer vos mots de passe, tout en assurant la confidentialité et la sécurité de vos données.

---

## Fonctionnalités principales

- **Génération de mots de passe**  
  Créez des mots de passe robustes selon des critères personnalisés (longueur, majuscules, chiffres, caractères spéciaux, etc.).

- **Évaluation de la force des mots de passe**  
  Analysez la complexité de vos mots de passe et obtenez des recommandations pour les renforcer.

- **Vérification des mots de passe compromis**  
  Utilise l’API Have I Been Pwned pour vérifier si un mot de passe a été exposé lors de fuites de données.

- **Chiffrement AES-GCM**  
  Les mots de passe sont chiffrés avant d’être sauvegardés, garantissant leur sécurité même en cas d’accès non autorisé aux fichiers.

- **Gestion du mot de passe maître**  
  Protégez l’accès à l’application avec un mot de passe maître fort, stocké de façon sécurisée (bcrypt, argon2, pbkdf2).

- **Historique et gestion des mots de passe**  
  Consultez l’historique des mots de passe générés, modifiez ou supprimez-les facilement.

- **Exportation et importation sécurisées**  
  Exportez ou importez vos mots de passe dans des fichiers chiffrés.

- **Encodage et décodage avancés**  
  Encodez ou décodez des chaînes dans de nombreux formats (base64, hex, base32, base58, base91, rot13, gzip, lzma, etc.).

- **Gestion des clés de chiffrement**  
  Générez, stockez et gérez les clés utilisées pour le chiffrement de vos données.

- **Suppression d’urgence**  
  Supprimez rapidement tous les mots de passe et données sensibles en cas de besoin.

- **Journalisation complète**  
  Toutes les actions importantes sont enregistrées dans un fichier de log (`password_manager.log`).

---

## Installation

1. **Cloner le dépôt :**
   ```bash
   git clone https://github.com/votre-utilisateur/keychain.git
   cd keychain
   ```

2. **Installer les dépendances :**
   ```bash
   pip install -r requirements.txt
   ```

---

## Utilisation

Lancez le programme principal :

```bash
python KeyChain.py
```

Suivez les instructions du menu interactif pour accéder à toutes les fonctionnalités.

---

## Dépendances principales

- `bcrypt`, `argon2-cffi`, `passlib` : Hachage sécurisé des mots de passe
- `pycryptodome` : Chiffrement AES-GCM
- `requests` : Requêtes HTTP (API Have I Been Pwned)
- `qrcode[pil]` : Génération de QR codes (si activé)
- `snappy`, `lz4`, `zstandard`, `brotli`, `lzma`, `bz2` : Algorithmes de compression avancés (optionnels)
- `colorama` : Affichage coloré en console

---

## Sécurité

- **Chiffrement fort** : AES-GCM avec dérivation de clé PBKDF2/Argon2.
- **Stockage sécurisé** : Permissions restrictives sur les fichiers sensibles.
- **Mot de passe maître** : Obligatoire, longueur minimale configurable.
- **Masquage des mots de passe** : Affichage masqué lors de la saisie.
- **Vérification en ligne** : Contrôle de la compromission des mots de passe.

---

## Journalisation

Un fichier `password_manager.log` est généré pour tracer toutes les actions importantes (création, modification, suppression, export, etc.).

---

## Contribution

Les contributions sont les bienvenues !  
Pour proposer une fonctionnalité ou corriger un bug, ouvrez une issue ou une pull request.

---

## Licence

Ce projet est sous licence MIT.  
Consultez le fichier `LICENSE` pour plus d’informations.

---
