import datetime
import json
import logging
import os
import sqlite3
from collections import Counter, defaultdict
from contextlib import contextmanager
from email.mime.text import MIMEText
from getpass import getpass
from typing import List, Optional, Tuple

import pyotp
import pyperclip  # Pour copier dans le presse-papiers
import yaml  # Pour export YAML
from colorama import Fore, Style, init

init(autoreset=True)

import bz2
import heapq
import lzma
import quopri
import secrets
from email.header import Header, decode_header

import brotli
import lz4.frame
import numpy as np
import snappy
import zstandard as zstd
from auth_manager import AuthManager
from config_manager import ConfigManager
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from encryption_manager import EncryptionManager
from evaluation_password import EvaluationPassword
from master_password_manager import MasterPasswordManager
from passlib.context import CryptContext
from password_generator import PasswordGenerator
from report_manager import ReportManager
from session_manager import SessionManager
from storage_manager import StorageManager


# ----------------- Storage Manager -----------------
class StorageManager:
    """Gestionnaire de stockage basé sur SQLite pour une meilleure sécurité et performance"""

    def __init__(self):
        self.conf = ConfigManager()
        self.passgen = PasswordGenerator()
        self.session = SessionManager()
        self.report = ReportManager()
        self.eval = EvaluationPassword()
        self.storage = StorageManager()
        self.enc = EncryptionManager()
        self.auth = AuthManager()
        self.master_manager = MasterPasswordManager(self.conf.secure_directory)

        self.master_password = None
        self.password_history = []
        self.secure_directory = self.load_secure_directory()
        self.derived_master_key = None
        self.pwd_context = CryptContext(
            schemes=["bcrypt", "argon2", "pbkdf2_sha256"], deprecated="auto"
        )
        self.setup_logging()

        self.db_path = os.path.join(self.secure_directory, "keychain.db")
        self.init_database()

    def setup_logging(self):
        logging.basicConfig(
            filename=os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "password_manager.log"
            ),
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )

    def load_secure_directory(self) -> str:
        config_file = os.path.join(os.path.expanduser("~"), "keychain_config.json")

        if os.path.exists(config_file):

            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            return config.get(
                "secure_directory", os.path.join(os.getcwd(), "secure_data")
            )
        print(Fore.YELLOW + "Fichier de configuration introuvable.")
        return self.conf.setup_secure_directory_interactive()

    @staticmethod
    def secure_file(filepath: str):

        if os.path.exists(filepath):
            os.chmod(filepath, 0o600)
            print(Fore.GREEN + f"Permissions appliquées pour : {filepath}")

        else:
            print(Fore.YELLOW + f"Fichier introuvable : {filepath}")

    def export_to_yaml(self, filepath: str):
        source = os.path.join(self.secure_directory, "passwords.txt")

        if os.path.exists(source):
            records = self.load_passwords(source)

            try:

                with open(filepath, "w", encoding="utf-8") as f:
                    yaml.dump(records, f, default_flow_style=False)
                print(Fore.GREEN + f"Export YAML réussi vers {filepath}.")

            except Exception as e:
                print(Fore.RED + f"Erreur lors de l'export YAML : {e}")

        else:
            print("Aucun mot de passe à exporter.")

    def verify_password(self, password, hashed_password):
        """
        Vérifie si un mot de passe correspond à son hachage.

        Parameters:
        password (str): Mot de passe en clair.
        hashed_password (str): Mot de passe haché.

        Returns:
        bool: True si le mot de passe correspond, False sinon.
        """
        return self.pwd_context.verify(password, hashed_password)

    def save_password_to_file(self, password, filename):
        """
        Sauvegarde un mot de passe haché dans un fichier et effectue une sauvegarde automatique.

        Parameters:
        password (str): Mot de passe à sauvegarder.
        filename (str): Nom du fichier.
        """
        if not self.master_manager.is_master_password_set():
            self.master_manager.set_master_password()
        master_pwd = self.master_manager.verify_master_password()
        if not master_pwd:
            print(
                "Authentification échouée. Impossible de sauvegarder le mot de passe."
            )
            return

        self.master_password = master_pwd

        try:
            hashed_password = self.enc.hash_password(
                password
            )  # Hachage du mot de passe
            self.create_or_append_file(filename, hashed_password, self.master_password)

            # Sauvegarde automatique dans un fichier de sauvegarde chiffré
            backup_file = os.path.join(
                self.secure_directory, "secure_data/passwords_backup.txt"
            )
            source_file = os.path.join(self.secure_directory, filename)
            if os.path.exists(source_file):
                with open(source_file, "rb") as file:
                    data = file.read()
                key = self.conf.manage_encryption_key()  # Utiliser une clé persistée
                encrypted_data, nonce, tag = self.enc.encrypt_password(
                    data.decode("utf-8"), key
                )
                with open(backup_file, "wb") as file:
                    file.write(
                        bytes(nonce) + b":" + bytes(tag) + b":" + bytes(encrypted_data)
                    )
                logging.info(f"Sauvegarde automatique effectuée dans {backup_file}")
                print(f"Une sauvegarde automatique a été effectuée dans {backup_file}")
            else:
                logging.warning(
                    "Aucun fichier source trouvé pour la sauvegarde automatique."
                )
                print("Aucun fichier source trouvé pour la sauvegarde automatique.")
        except Exception as e:
            print(f"Erreur lors de la sauvegarde du mot de passe : {e}")
            return

        print("\nMot de passe sauvegardé avec succès!")

    def add_password_to_history(self, password):
        """
        Ajoute un mot de passe à l'historique avec la date actuelle après authentification.

        Parameters:
        password (str): Mot de passe à ajouter.
        """
        if not self.auth.authenticate_master_password_once():
            return

        current_date = datetime.datetime.now()
        self.password_history.append((password, current_date))
        self.clean_old_passwords()

    def clean_old_passwords(self):
        """
        Supprime les mots de passe de l'historique datant de plus de 30 jours.
        """
        current_date = datetime.datetime.now()
        while (
            self.password_history
            and (current_date - self.password_history[0][1]).days > 30
        ):
            self.password_history.pop(
                0
            )  # Supprime le mot de passe le plus ancien (FIFO)

    def view_passwords_last_30_days(self):
        """
        Affiche les mots de passe générés au cours des 30 derniers jours après authentification.

        Returns:
        None
        """
        if not self.auth.authenticate_master_password_once():
            return

        print("\nMots de passe générés au cours des 30 derniers jours :")
        current_date = datetime.datetime.now()
        filtered_passwords = [
            (pwd, date)
            for pwd, date in self.password_history
            if (current_date - date).days <= 30
        ]

        if not filtered_passwords:
            print("Aucun mot de passe généré au cours des 30 derniers jours.")
        else:
            for i, (pwd, date) in enumerate(filtered_passwords, 1):
                print(f"{i}. {pwd} (généré le {date.strftime('%Y-%m-%d %H:%M:%S')})")

    def delete_compromised_passwords(self):
        """
        Supprime automatiquement les mots de passe compromis après confirmation et génère un rapport.

        Returns:
        None
        """
        self.conf.setup_secure_directory()
        filepath = os.path.join(self.secure_directory, "passwords.txt")
        if os.path.exists(filepath):
            with open(filepath, "rb") as file:
                passwords = file.readlines()
            safe_passwords = []
            compromised_passwords = []
            key = self.conf.manage_encryption_key()  # Récupérer la clé persistée
            for line in passwords:
                try:
                    salt, nonce, tag, encrypted_password = line.split(b":")
                    derived_key = self.enc.derive_key_from_master_password(
                        self.master_password, salt
                    )
                    password = self.enc.decrypt_password(
                        encrypted_password, derived_key, nonce, tag
                    )
                    if self.eval.check_password_breach(password):
                        compromised_passwords.append(password)
                    else:
                        safe_passwords.append(line)
                except Exception as e:
                    print(f"Erreur lors de la vérification d'un mot de passe : {e}")

            if compromised_passwords:
                print(
                    "\nLes mots de passe suivants sont compromis et seront supprimés :"
                )
                for pwd in compromised_passwords:
                    print(self.conf.mask_password(pwd))

                confirmation = (
                    input("Confirmez-vous la suppression ? (oui/non) : ")
                    .strip()
                    .lower()
                )
                if confirmation == "oui":
                    with open(filepath, "wb") as file:
                        file.writelines(safe_passwords)
                    print("Les mots de passe compromis ont été supprimés.")

                    # Générer un rapport des mots de passe compromis
                    report_path = os.path.join(
                        self.secure_directory, "compromised_passwords_report.json"
                    )
                    with open(report_path, "w", encoding="utf-8") as report_file:
                        json.dump(compromised_passwords, report_file, indent=4)
                    print(f"Rapport des mots de passe compromis généré : {report_path}")
                else:
                    print("Suppression annulée.")
            else:
                print("Aucun mot de passe compromis trouvé.")
        else:
            print("Aucun mot de passe enregistré.")

    def analyze_saved_passwords(self):
        """
        Analyse les mots de passe enregistrés pour identifier les faiblesses et génère un rapport.

        Returns:
        None
        """
        filepath = os.path.join(self.secure_directory, "passwords.txt")
        if os.path.exists(filepath):
            with open(filepath, "rb") as file:
                passwords = [line.decode("utf-8").strip() for line in file.readlines()]

            print("\nAnalyse des mots de passe enregistrés :")
            report = []
            for i, password in enumerate(passwords, 1):
                strength = self.eval.check_password_strength(password)
                compromised = self.eval.check_password_breach(password)
                status = "Compromis" if compromised else "Sûr"
                print(
                    f"{i}. {self.conf.mask_password(password)} - Force : {strength} - Statut : {status}"
                )
                report.append(
                    {
                        "index": i,
                        "password": self.conf.mask_password(password),
                        "strength": strength,
                        "status": status,
                    }
                )

            # Générer un rapport exportable
            report_path = os.path.join(
                self.secure_directory, "password_analysis_report.json"
            )
            with open(report_path, "w", encoding="utf-8") as report_file:
                json.dump(report, report_file, indent=4)
            print(f"\nRapport d'analyse généré : {report_path}")
        else:
            print("Aucun mot de passe enregistré.")

    def remind_password_update(self):
        """
        Rappelle à l'utilisateur de mettre à jour les mots de passe vieux de plus de 90 jours et envoie des notifications.

        Returns:
        None
        """
        current_date = datetime.datetime.now()
        outdated_passwords = [
            (pwd, date)
            for pwd, date in self.password_history
            if (current_date - date).days > 90
        ]

        if outdated_passwords:
            print("\nLes mots de passe suivants doivent être mis à jour :")
            for i, (pwd, date) in enumerate(outdated_passwords, 1):
                print(
                    f"{i} - {self.conf.mask_password(pwd)} (créé le {date.strftime('%Y-%m-%d')})"
                )

            # Envoi d'une notification par e-mail
            email = input(
                "Entrez votre adresse e-mail pour recevoir un rappel : "
            ).strip()
            if email:
                try:
                    message = "Les mots de passe suivants doivent être mis à jour :\n"
                    for i, (pwd, date) in enumerate(outdated_passwords, 1):
                        message += f"{i} - {self.conf.mask_password(pwd)} (créé le {date.strftime('%Y-%m-%d')})\n"
                    self.session.send_security_alert(email, message)
                    print("Rappel envoyé par e-mail.")
                except Exception as e:
                    print(f"Erreur lors de l'envoi du rappel : {e}")
        else:
            print("Tous les mots de passe sont à jour.")

    def export_passwords(self, filepath):
        """
        Exporte les mots de passe enregistrés dans un fichier chiffré ou CSV.

        Parameters:
        filepath (str): Chemin du fichier d'exportation.

        Returns:
        None
        """
        self.conf.setup_secure_directory()
        source_file = os.path.join(self.secure_directory, "passwords.txt")
        if os.path.exists(source_file):
            format_choice = input(
                "Choisissez le format d'exportation (1: chiffré, 2: CSV) : "
            ).strip()
            if format_choice == "1":
                with open(source_file, "rb") as file:
                    data = file.read()
                key = self.conf.manage_encryption_key()  # Utiliser une clé persistée
                encrypted_data, nonce, tag = self.enc.encrypt_password(
                    data.decode("utf-8"), key
                )
                with open(filepath, "wb") as export_file:
                    export_file.write(
                        b"".join([nonce, b":", tag, b":", encrypted_data])
                    )
                print(f"Mots de passe exportés dans {filepath} (chiffré).")
            elif format_choice == "2":
                passwords = self.load_passwords(source_file)
                self.export_passwords_to_csv(passwords, filepath)
            else:
                print("Option invalide. Exportation annulée.")
        else:
            print("Aucun mot de passe à exporter.")

    def analyze_password_statistics(self, passwords):
        """
        Analyse les mots de passe pour fournir des statistiques.
        """
        lengths = [len(pwd) for pwd in passwords]
        char_types = Counter(char for pwd in passwords for char in pwd)

        print(f"Nombre total de mots de passe : {len(passwords)}")
        print(f"Longueur moyenne : {sum(lengths) / len(lengths):.2f}")
        print(f"Caractères les plus fréquents : {char_types.most_common(5)}")

    def emergency_delete_all_passwords(self):
        """
        Supprime tous les mots de passe enregistrés en cas d'urgence.

        Returns:
        None
        """
        confirmation = (
            input(
                "Êtes-vous sûr de vouloir supprimer tous les mots de passe ? (oui/non) : "
            )
            .strip()
            .lower()
        )
        if confirmation == "oui":
            filepath = os.path.join(self.secure_directory, "passwords.txt")
            if os.path.exists(filepath):
                os.remove(filepath)
                print("Tous les mots de passe ont été supprimés.")
            else:
                print("Aucun mot de passe enregistré à supprimer.")
        else:
            print("Suppression annulée.")

    def search_password(self, keyword):
        """
        Recherche un mot de passe enregistré par mot-clé.

        Parameters:
        keyword (str): Mot-clé à rechercher.

        Returns:
        None
        """
        filepath = os.path.join(self.secure_directory, "passwords.txt")
        if os.path.exists(filepath):
            with open(filepath, "rb") as file:
                passwords = file.readlines()
            results = [
                line.decode("utf-8").strip()
                for line in passwords
                if keyword.lower() in line.decode("utf-8").lower()
            ]
            if results:
                print("\nRésultats de la recherche :")
                for i, result in enumerate(results, 1):
                    print(f"{i} - {self.conf.mask_password(result)}")
            else:
                print("Aucun mot de passe correspondant trouvé.")
        else:
            print("Aucun mot de passe enregistré.")

    # Méthode importée depuis security_audit.py
    def audit_passwords(self, passwords):
        """
        Audite les mots de passe pour identifier les faiblesses.
        """
        weak_passwords = [pwd for pwd in passwords if len(pwd) < 8]
        print(f"Mots de passe faibles : {len(weak_passwords)}")

    # Méthode importée depuis password_history.py
    def log_password_change(self, password, action):
        """
        Journalise une modification de mot de passe.
        """
        with open("password_history.log", "a", encoding="utf-8") as file:
            file.write(f"{datetime.datetime.now()} - {action}: {password}\n")

    # Méthode importée depuis password_generator.py

    # Méthode importée depuis password_analysis.py
    def analyze_passwords(self, passwords):
        """
        Analyse les mots de passe pour fournir des statistiques.
        """
        lengths = [len(pwd) for pwd in passwords]
        char_types = Counter(char for pwd in passwords for char in pwd)

        print(f"Nombre total de mots de passe : {len(passwords)}")
        print(f"Longueur moyenne : {sum(lengths) / len(lengths):.2f}")
        print(f"Caractères les plus fréquents : {char_types.most_common(5)}")

    def create_or_append_file(self, filename, password, master_password):
        """
        Ajoute ou crée un fichier pour stocker un mot de passe chiffré avec son index, date de modification et date de suppression.

        Parameters:
        filename (str): Nom du fichier.
        password (str): Mot de passe à stocker.
        master_password (str): Mot de passe maître pour dériver la clé.
        """
        self.conf.setup_secure_directory()
        filepath = os.path.join(self.secure_directory, filename)
        salt = get_random_bytes(16)
        key = self.enc.derive_key_from_master_password(master_password, salt)
        encrypted_password, nonce, tag = self.enc.encrypt_password(password, key)

        current_date = datetime.datetime.now()
        deletion_date = current_date + datetime.timedelta(
            days=30
        )  # Suppression automatique après 30 jours

        # Charger les mots de passe existants
        passwords = self.load_passwords(filepath)

        # Ajouter un nouvel index
        new_index = len(passwords) + 1
        passwords.append(
            {
                "index": new_index,
                "encrypted_password": base64.b64encode(
                    salt + b":" + nonce + b":" + tag + b":" + encrypted_password
                ).decode("utf-8"),
                "modified_date": current_date.strftime("%Y-%m-%d %H:%M:%S"),
                "deletion_date": deletion_date.strftime("%Y-%m-%d %H:%M:%S"),
            }
        )

        # Sauvegarder les mots de passe mis à jour
        self.save_passwords(passwords, filepath)
        print(f"Mot de passe ajouté avec succès avec l'index {new_index}.")

    def save_passwords(self, passwords, filepath):
        """
        Sauvegarde une liste de mots de passe dans un fichier JSON.

        Parameters:
        passwords (list): Liste des mots de passe.
        filepath (str): Chemin du fichier.
        """
        with open(filepath, "w", encoding="utf-8") as file:
            json.dump(passwords, file, indent=4)
        self.secure_file(filepath)

    def load_passwords(self, filepath):
        """
        Charge une liste de mots de passe depuis un fichier JSON.

        Parameters:
        filepath (str): Chemin du fichier.

        Returns:
        list: Liste des mots de passe chargés.
        """
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as file:
                return json.load(file)
        return []

    def delete_expired_passwords(self, filename):
        """
        Supprime les mots de passe dont la date de suppression automatique est dépassée après confirmation.

        Parameters:
        filename (str): Nom du fichier contenant les mots de passe.
        """
        filepath = os.path.join(self.secure_directory, filename)
        passwords = self.load_passwords(filepath)
        current_date = datetime.datetime.now()

        expired_passwords = [
            pwd
            for pwd in passwords
            if datetime.datetime.strptime(pwd["deletion_date"], "%Y-%m-%d %H:%M:%S")
            <= current_date
        ]

        if expired_passwords:
            print("\nLes mots de passe suivants sont expirés et seront supprimés :")
            for pwd in expired_passwords:
                print(
                    f"Index: {pwd['index']}, Date de suppression : {pwd['deletion_date']}"
                )

            confirmation = (
                input("Confirmez-vous la suppression ? (oui/non) : ").strip().lower()
            )
            if confirmation == "oui":
                updated_passwords = [
                    pwd
                    for pwd in passwords
                    if datetime.datetime.strptime(
                        pwd["deletion_date"], "%Y-%m-%d %H:%M:%S"
                    )
                    > current_date
                ]
                self.save_passwords(updated_passwords, filepath)
                print("Les mots de passe expirés ont été supprimés.")
            else:
                print("Suppression annulée.")
        else:
            print("Aucun mot de passe expiré à supprimer.")

    def list_saved_passwords(self, filename):
        """
        Liste tous les mots de passe enregistrés avec leur index, date de modification et date de suppression.

        Parameters:
        filename (str): Nom du fichier contenant les mots de passe.
        """
        filepath = os.path.join(self.secure_directory, filename)
        passwords = self.load_passwords(filepath)

        if passwords:
            print("\nMots de passe enregistrés :")
            for pwd in passwords:
                print(
                    (
                        f"Index: {pwd['index']}, Date de modification: {pwd['modified_date']}, "
                        f"Date de suppression: {pwd['deletion_date']}"
                    )
                )
        else:
            print("Aucun mot de passe enregistré.")

    def reveal_password(self, filename, index):
        """
        Affiche un mot de passe spécifique en clair après authentification.

        Parameters:
        filename (str): Nom du fichier contenant les mots de passe.
        index (int): Index du mot de passe à afficher.
        """
        filepath = os.path.join(self.secure_directory, filename)
        passwords = self.load_passwords(filepath)

        for pwd in passwords:
            if pwd["index"] == index:
                encrypted_data = base64.b64decode(pwd["encrypted_password"])
                salt, nonce, tag, encrypted_password = encrypted_data.split(b":")
                key = self.enc.derive_key_from_master_password(
                    self.master_password, salt
                )
                try:
                    decrypted_password = self.enc.decrypt_password(
                        encrypted_password, key, nonce, tag
                    )
                    print(
                        f"Mot de passe en clair (index {index}): {decrypted_password}"
                    )
                    return
                except Exception as e:
                    print(f"Erreur lors du déchiffrement : {e}")
                    return

        print(f"Aucun mot de passe trouvé avec l'index {index}.")

    # Méthode importée depuis i18n.py
    def load_translations(self, language):
        """
        Charge les traductions pour une langue donnée.
        """
        try:
            with open(f"translations_{language}.json", "r", encoding="utf-8") as file:
                return json.load(file)
        except FileNotFoundError:
            print(f"Traductions introuvables pour la langue : {language}")
            return {}

    # Méthode importée depuis categories.py
    def organize_passwords_by_category(self, passwords):
        """
        Organise les mots de passe par catégorie.
        """
        categories = defaultdict(list)
        for pwd in passwords:
            category = pwd.get("category", "Uncategorized")
            categories[category].append(pwd)
        return categories

    @staticmethod
    def export_passwords_to_csv(records, filepath: str):

        try:

            with open(filepath, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["site", "username", "password"])
                writer.writeheader()
                writer.writerows(records)
            print(Fore.GREEN + f"Export CSV réussi vers {filepath}.")

        except Exception as e:
            print(Fore.RED + f"Erreur lors de l'export CSV : {e}")

    def generate_qr_code(self, pwd: str):

        try:

            import qrcode

            qr = qrcode.QRCode()
            qr.add_data(pwd)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img_path = os.path.join(self.storage.secure_directory, "qrcode.png")
            img.save(img_path)
            print(Fore.GREEN + f"QR code généré : {img_path}")
            validity = input(
                "Durée de validité (minutes, vide pour illimité) : "
            ).strip()

            if validity.isdigit():
                minutes = int(validity)
                exp = datetime.datetime.now() + datetime.timedelta(minutes=minutes)
                print(Fore.CYAN + f"Expirera le : {exp.strftime('%Y-%m-%d %H:%M:%S')}")

        except ImportError:
            print(
                "Module qrcode manquant. Installez-le avec 'pip install qrcode[pil]'."
            )

    def import_passwords_from_csv(self, path: str):

        try:

            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                count = sum(1 for _ in reader)
            print(Fore.GREEN + f"{count} mots de passe importés depuis {path}.")

        except Exception as e:
            print(Fore.RED + f"Erreur d'import CSV : {e}")

    def auto_breach_check(self):
        filepath = os.path.join(self.secure_directory, "passwords.txt")
        compromised = []

        if os.path.exists(filepath):

            for r in self.storage.load_passwords(filepath):

                try:
                    data = base64.b64decode(r["encrypted_password"])
                    salt, nonce, tag, encrypted = data.split(b":")
                    key = self.enc.derive_key_from_master_password(
                        auth._master_plaintext, salt
                    )
                    pwd = self.enc.decrypt_password(encrypted, key, nonce, tag)

                    if eval.check_password_breach(pwd):
                        compromised.append(r)

                except Exception:

                    continue

            if compromised:
                print(Fore.RED + "Des mots de passe compromis ont été détectés.")
                email = input("Adresse e-mail pour alerte automatique : ").strip()

                if email:
                    msg = "".join(f"Index: {r.get('index')}\n" for r in compromised)
                    return email, msg
                print("Aucune alerte envoyée, adresse manquante.")

        else:
            print("Aucun mot de passe pour vérification.")

    def init_database(self):
        """Initialise la base de données SQLite avec le schéma requis"""
        with self.get_db() as (conn, cur):
            # Table des mots de passe
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    username TEXT,
                    password_hash TEXT NOT NULL,
                    url TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Table historique des mots de passe
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_id INTEGER,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (password_id) REFERENCES passwords(id)
                )
            """
            )

            # Table des métadonnées de sécurité
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS security_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_id INTEGER,
                    salt TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    kdf_params TEXT NOT NULL,
                    FOREIGN KEY (password_id) REFERENCES passwords(id)
                )
            """
            )
            conn.commit()

    @contextmanager
    def get_db(self):
        """Context manager pour la connexion à la base de données"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn, conn.cursor()
        finally:
            conn.close()

    def save_password_to_db(
        self,
        title: str,
        username: str,
        password: str,
        url: str = None,
        notes: str = None,
    ):
        """Sauvegarde un nouveau mot de passe de façon sécurisée"""
        if self.master_password is None:
            raise ValueError("Le mot de passe maître n'est pas défini")

        # Génération des données de sécurité
        salt = self.enc.generate_salt()
        password_hash = self.enc.hash_password(password, salt)
        iv, tag = self.enc.generate_encryption_params()
        kdf_params = json.dumps(self.enc.get_kdf_params())

        with self.get_db() as (conn, cur):
            try:
                # Insertion du mot de passe
                cur.execute(
                    """
                    INSERT INTO passwords (title, username, password_hash, url, notes)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (title, username, password_hash, url, notes),
                )

                password_id = cur.lastrowid

                # Insertion des métadonnées de sécurité
                cur.execute(
                    """
                    INSERT INTO security_metadata (password_id, salt, iv, tag, kdf_params)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (password_id, salt.hex(), iv.hex(), tag.hex(), kdf_params),
                )

                conn.commit()
                logging.info(f"Mot de passe sauvegardé pour {title}")
                return True

            except Exception as e:
                conn.rollback()
                logging.error(f"Erreur lors de la sauvegarde: {e}")
                raise

    def get_password(self, title: str) -> Optional[dict]:
        """Récupère un mot de passe et ses métadonnées"""
        with self.get_db() as (conn, cur):
            cur.execute(
                """
                SELECT p.*, sm.salt, sm.iv, sm.tag
                FROM passwords p
                JOIN security_metadata sm ON p.id = sm.password_id
                WHERE p.title = ?
            """,
                (title,),
            )
            row = cur.fetchone()

            if row:
                return dict(row)
            return None

    def list_passwords(self) -> List[dict]:
        """Liste tous les mots de passe stockés"""
        with self.get_db() as (conn, cur):
            cur.execute("SELECT title, username, url, created_at FROM passwords")
            return [dict(row) for row in cur.fetchall()]

    def delete_password(self, title: str) -> bool:
        """Supprime un mot de passe et ses données associées"""
        with self.get_db() as (conn, cur):
            try:
                cur.execute("SELECT id FROM passwords WHERE title = ?", (title,))
                password_id = cur.fetchone()

                if not password_id:
                    return False

                password_id = password_id[0]

                # Suppression en cascade
                cur.execute(
                    "DELETE FROM security_metadata WHERE password_id = ?",
                    (password_id,),
                )
                cur.execute(
                    "DELETE FROM password_history WHERE password_id = ?", (password_id,)
                )
                cur.execute("DELETE FROM passwords WHERE id = ?", (password_id,))

                conn.commit()
                return True

            except Exception as e:
                conn.rollback()
                logging.error(f"Erreur lors de la suppression: {e}")
                return False

    def update_password(self, title: str, new_password: str) -> bool:
        """Met à jour un mot de passe existant"""
        if self.master_password is None:
            raise ValueError("Le mot de passe maître n'est pas défini")

        with self.get_db() as (conn, cur):
            try:
                # Récupération de l'ancien mot de passe
                cur.execute(
                    "SELECT id, password_hash FROM passwords WHERE title = ?", (title,)
                )
                row = cur.fetchone()
                if not row:
                    return False

                password_id, old_hash = row["id"], row["password_hash"]

                # Sauvegarde dans l'historique
                cur.execute(
                    """
                    INSERT INTO password_history (password_id, password_hash)
                    VALUES (?, ?)
                """,
                    (password_id, old_hash),
                )

                # Mise à jour du mot de passe
                new_hash = self.enc.hash_password(new_password)
                cur.execute(
                    """
                    UPDATE passwords
                    SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """,
                    (new_hash, password_id),
                )

                conn.commit()
                return True

            except Exception as e:
                conn.rollback()
                logging.error(f"Erreur lors de la mise à jour: {e}")
                return False

    def migrate_from_files(self):
        """Migration des données depuis l'ancien système de fichiers"""
        old_file = os.path.join(self.secure_directory, "passwords.txt")
        if not os.path.exists(old_file):
            return

        try:
            with open(old_file, "r") as f:
                old_data = json.load(f)

            for entry in old_data:
                self.save_password_to_db(
                    title=entry.get("title", "Imported Password"),
                    username=entry.get("username", ""),
                    password=entry.get("password", ""),
                    url=entry.get("url", ""),
                    notes=entry.get("notes", ""),
                )

            # Backup ancien fichier
            os.rename(old_file, old_file + ".bak")
            logging.info("Migration réussie depuis l'ancien système")

        except Exception as e:
            logging.error(f"Erreur lors de la migration: {e}")
            raise
