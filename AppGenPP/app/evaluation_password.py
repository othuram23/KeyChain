import base64
import hashlib
import json
import logging
import os
import string

import requests
from auth_manager import AuthManager
from colorama import Fore, Style, init
from config_manager import ConfigManager
from encryption_manager import EncryptionManager
from master_password_manager import MasterPasswordManager
from password_generator import PasswordGenerator
from report_manager import ReportManager
from session_manager import SessionManager
from storage_manager import StorageManager

# Pour export YAML


init(autoreset=True)


class EvaluationPassword:

    def __init__(self):
        self.conf = ConfigManager()
        self.passgen = PasswordGenerator()
        self.session = SessionManager()
        self.report = ReportManager()
        # Correction : éviter la récursivité infinie
        # self.eval = EvaluationPassword()  # Supprimé car cela crée une récursivité infinie
        self.storage = StorageManager()
        self.enc = EncryptionManager()
        self.auth = AuthManager()
        self.master_manager = MasterPasswordManager(self.conf.secure_directory)

    @staticmethod
    def check_password_strength(password: str) -> int:
        """Retourne un score indiquant la robustesse du mot de passe."""
        score = 0
        # Vérifie la présence de chaque type de caractère
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        types = sum([has_upper, has_lower, has_digit, has_special])
        score += types
        # Bonus pour la longueur
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        if len(password) >= 20:
            score += 1
        return score

    @staticmethod
    def check_password(
        password: str, common_passwords_path: str = "common.txt"
    ) -> None:
        """Vérifie le mot de passe pour divers problèmes et affiche un message sur sa robustesse."""
        common_passwords: set[str] = set()
        if os.path.exists(common_passwords_path):
            try:
                with open(common_passwords_path, "r", encoding="utf-8") as f:
                    common_passwords = set(f.read().splitlines())
            except Exception:
                pass
        if password in common_passwords:
            print("Le mot de passe est trop commun. Sa robustesse est 0.")
            return
        print(
            f"Force du mot de passe : {EvaluationPassword.evaluate_password_strength(password, list(common_passwords))}"
        )
        for rec in EvaluationPassword.quality_recommendations(password):
            print(f"- {rec}")

    def evaluate_password_menu(self):
        password = input("\nEntrez le mot de passe à évaluer: ").strip()
        common_patterns_path = os.path.join(
            self.storage.secure_directory, "common_patterns.txt"
        )
        common_patterns = []
        if os.path.exists(common_patterns_path):
            try:
                with open(common_patterns_path, "r", encoding="utf-8") as f:
                    common_patterns = f.read().splitlines()
            except Exception:
                pass
        print(
            f"\nForce du mot de passe: {EvaluationPassword.evaluate_password_strength(password, common_patterns)}"
        )
        for rec in EvaluationPassword.quality_recommendations(password):
            print(f"- {rec}")

    @staticmethod
    def evaluate_password_strength(password: str, common_patterns) -> str:
        """Évalue la force du mot de passe et retourne une chaîne descriptive."""
        if common_patterns is None:
            common_patterns = []
        if password in common_patterns:
            return "Trop commun"
        score = EvaluationPassword.check_password_strength(password)
        # Optimisation : mapping score -> label
        labels = [
            "Très faible",
            "Très faible",
            "Faible",
            "Moyen",
            "Correct",
            "Fort",
            "Excellent",
            "Excellent",
            "Excellent",
        ]
        return labels[score] if score < len(labels) else "Excellent"

    from typing import List

    @staticmethod
    def quality_recommendations(password: str) -> List[str]:
        recs = []
        if len(password) < 12:
            recs.append("Augmenter la longueur à au moins 12 caractères.")
        if not any(c.isupper() for c in password):
            recs.append("Ajouter des lettres majuscules.")
        if not any(c.islower() for c in password):
            recs.append("Ajouter des lettres minuscules.")
        if not any(c.isdigit() for c in password):
            recs.append("Ajouter des chiffres.")
        if not any(c in string.punctuation for c in password):
            recs.append("Ajouter des caractères spéciaux.")
        return recs

    @staticmethod
    def check_password_breach(password):
        """
        Vérifie si un mot de passe a été compromis via l'API Have I Been Pwned.
        """
        try:
            sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix, suffix = sha1_password[:5], sha1_password[5:]
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            hashes = response.text.splitlines()
            return any(h.startswith(suffix) for h in hashes)
        except requests.RequestException as e:
            print(f"Erreur réseau lors de la vérification du mot de passe : {e}")
            return False
        except Exception as e:
            print(f"Erreur inattendue lors de la vérification du mot de passe : {e}")
            return False

    @staticmethod
    def estimate_crack_time(password):
        """
        Estime le temps nécessaire pour deviner un mot de passe via une attaque par force brute.
        """
        char_space = 0
        if any(c.islower() for c in password):
            char_space += 26  # Lettres minuscules
        if any(c.isupper() for c in password):
            char_space += 26  # Lettres majuscules
        if any(c.isdigit() for c in password):
            char_space += 10  # Chiffres
        if any(c in string.punctuation for c in password):
            char_space += len(string.punctuation)  # Caractères spéciaux

        total_combinations = char_space ** len(password)
        guesses_per_second = 1e9  # Hypothèse : 1 milliard de tentatives par seconde
        seconds = total_combinations / guesses_per_second

        # Documentation des hypothèses
        print(
            "Hypothèse : 1 milliard de tentatives par seconde pour une attaque par force brute."
        )
        if seconds < 60:
            return f"{seconds:.2f} secondes"
        elif seconds < 3600:
            return f"{seconds / 60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.2f} heures"
        elif seconds < 31536000:
            return f"{seconds / 86400:.2f} jours"
        else:
            return f"{seconds / 31536000:.2f} années"

    def analyze_and_evaluate_passwords(self) -> None:

        while not self.auth.authenticate_master_password_once():
            print("Authentification échouée. Veuillez réessayer.")
        print("\nChoisissez le mode d'analyse :")
        print("1 - Évaluer un mot de passe individuel")
        print("2 - Analyser tous les mots de passe enregistrés et générer un rapport")
        mode = input("Votre choix (1/2) : ").strip()
        common_patterns = []
        common_file = os.path.join(self.storage.secure_directory, "common_patterns.txt")
        if os.path.exists(common_file):
            try:
                with open(common_file, "r", encoding="utf-8") as f:
                    common_patterns = f.read().splitlines()
            except Exception as e:
                print(f"Erreur lors du chargement des motifs courants : {e}")
        if mode == "1":
            password = input("Entrez le mot de passe à évaluer : ").strip()
            if not password:
                print("Aucun mot de passe fourni.")
                return
            print(
                f"\nForce du mot de passe : {EvaluationPassword.evaluate_password_strength(password, common_patterns)}"
            )
            for rec in filter(
                None, EvaluationPassword.quality_recommendations(password)
            ):
                print(f"- {rec}")
        elif mode == "2":
            filepath = os.path.join(self.storage.secure_directory, "passwords.json")
            records = self.storage.load_passwords(filepath)
            if not records:
                print("Aucun mot de passe enregistré.")
                return
            report = []
            print("\nAnalyse des mots de passe enregistrés :")
            for rec in records:
                try:
                    data = base64.b64decode(rec["encrypted_data"])
                    salt = data[:16]
                    nonce = data[16:28]
                    tag = data[28:44]
                    encrypted = data[44:]
                    key = self.enc.derive_key_from_master_password(
                        self.auth._master_plaintext, salt
                    )
                    plain = self.enc.decrypt_password(encrypted, key, nonce, tag)
                    strength = EvaluationPassword.evaluate_password_strength(
                        plain, common_patterns
                    )
                    compromised = (
                        "Compromis"
                        if EvaluationPassword.check_password_breach(plain)
                        else "Sûr"
                    )
                    print(
                        f"Index {rec.get('index', '?')} : {plain} - Force: {strength} - Statut: {compromised}"
                    )
                    report.append(
                        {
                            "index": rec.get("index", "?"),
                            "password": plain,
                            "strength": strength,
                            "status": compromised,
                        }
                    )
                except Exception as e:
                    print(f"Erreur pour l'enregistrement {rec.get('index', '?')} : {e}")
            report_path = os.path.join(
                self.storage.secure_directory, "password_analysis_report.json"
            )
            try:
                with open(report_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=4)
                print(Fore.GREEN + f"Rapport d'analyse généré : {report_path}")
            except Exception as e:
                print(Fore.RED + f"Erreur lors de la sauvegarde du rapport : {e}")
        else:
            print("Mode invalide. Veuillez choisir 1 ou 2.")
        logging.info("Analyse et évaluation des mots de passe effectuée.")
