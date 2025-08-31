import base64
import binascii
import codecs
import csv
import datetime
import gzip
import hashlib
import hmac
import json
import logging
import os
import random
import smtplib
import string
import time
import zlib

import requests
from colorama import Fore, Style, init

init(autoreset=True)

from auth_manager import AuthManager
from config_manager import ConfigManager
from encryption_manager import EncryptionManager
from evaluation_password import EvaluationPassword
from master_password_manager import MasterPasswordManager
from passlib.context import CryptContext
from password_generator import PasswordGenerator
from report_manager import ReportManager
from session_manager import SessionManager
from storage_manager import StorageManager


# ----------------- Report Manager -----------------
class ReportManager:

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
        self.secure_directory = self.storage.load_secure_directory()
        self.derived_master_key = None
        self.pwd_context = CryptContext(
            schemes=["bcrypt", "argon2", "pbkdf2_sha256"], deprecated="auto"
        )
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            filename=os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "password_manager.log"
            ),
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )

    def analyze_saved_passwords(
        self, storage: StorageManager, enc: EncryptionManager, auth: AuthManager
    ):
        filepath = os.path.join(storage.secure_directory, "passwords.txt")

        if os.path.exists(filepath):
            # Demande du mot de passe maître pour déchiffrement
            master_pwd = self.master_manager.verify_master_password()
            if not master_pwd:
                print("Authentification échouée.")
                return
            records = storage.load_passwords(filepath)
            report = []

            for i, r in enumerate(records, 1):

                try:
                    data = base64.b64decode(r["encrypted_password"])
                    salt, nonce, tag, encrypted = data.split(b":")
                    key = enc.derive_key_from_master_password(master_pwd, salt)
                    pwd = enc.decrypt_password(encrypted, key, nonce, tag)

                except Exception:
                    pwd = "Inaccessible"
                strength = eval.evaluate_password_strength(pwd, [])
                status = (
                    "Compromis"
                    if pwd != "Inaccessible" and self.eval.check_password_breach(pwd)
                    else "Sûr"
                )
                report.append(
                    {
                        "index": i,
                        "password": "*" * len(pwd),
                        "strength": strength,
                        "status": status,
                    }
                )
                print(f"{i}. {'*' * len(pwd)} - Force : {strength} - Statut : {status}")
            report_path = os.path.join(
                storage.secure_directory, "password_analysis_report.json"
            )

            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=4)
            print(Fore.GREEN + f"Rapport généré : {report_path}")

        else:
            print("Aucun mot de passe enregistré.")

    def generate_detailed_report(
        self, storage: StorageManager, enc: EncryptionManager, auth: AuthManager
    ):
        filepath = os.path.join(storage.secure_directory, "passwords.txt")

        if os.path.exists(filepath):
            # Demande du mot de passe maître pour déchiffrement
            master_pwd = self.master_manager.verify_master_password()
            if not master_pwd:
                print("Authentification échouée.")
                return
            records = storage.load_passwords(filepath)
            lengths, recommendations = [], []

            for r in records:

                try:
                    data = base64.b64decode(r["encrypted_password"])
                    salt, nonce, tag, encrypted = data.split(b":")
                    key = enc.derive_key_from_master_password(master_pwd, salt)
                    pwd = enc.decrypt_password(encrypted, key, nonce, tag)
                    lengths.append(len(pwd))
                    recommendations.extend(eval.quality_recommendations(pwd))

                except Exception:
                    continue
            avg_length = sum(lengths) / len(lengths) if lengths else 0
            report = {
                "total_passwords": len(records),
                "average_length": avg_length,
                "recommendations": list(set(recommendations)),
            }
            report_file = os.path.join(storage.secure_directory, "detailed_report.json")

            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=4)
            print(Fore.GREEN + f"Rapport détaillé généré : {report_file}")

        else:
            print("Aucun mot de passe enregistré.")

    def search_password(self, keyword: str):
        filepath = os.path.join(self.storage.secure_directory, "passwords.txt")

        if os.path.exists(filepath):
            results = [
                r
                for r in self.storage.load_passwords(filepath)
                if keyword.lower() in json.dumps(r).lower()
            ]

            if results:

                for i, r in enumerate(results, 1):
                    print(
                        f"{i} - Index: {r.get('index')}, Tags: {r.get('tags')}, Mot de passe masqué: {self.conf.mask_password(r.get('encrypted_password'))}"
                    )

            else:
                print("Aucun résultat trouvé.")

        else:
            print("Aucun mot de passe enregistré.")
