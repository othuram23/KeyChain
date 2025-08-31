# -*- coding: utf-8 -*-
"""
Created on Mon Jul 29 20:04:24 2024

Author: Thuram OTCHOUN

Description:
Gestionnaire de mots de passe sécurisé enrichi.
Fonctionnalités intégrées :
 - Authentification maître et 2FA
 - Chiffrement/Déchiffrement avec une large gamme d'encodeurs/décodeurs (50 méthodes)
 - Sauvegarde locale et cloud (simulation)
 - Gestion multi-utilisateur
 - Génération, analyse et rapports détaillés
 - Export vers CSV et YAML
 - Historisation, rappels de mise à jour et vérification de qualité
 - Copie dans le presse-papiers
 - Gestion de session (déconnexion après inactivité)
 - Interface CLI améliorée avec couleurs
La logique interne de chaque module est préservée et les fonctionnalités fusionnées se complètent.
"""

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
from collections import Counter, defaultdict
from email.mime.text import MIMEText
from getpass import getpass
from typing import Self

import pyotp
import pyperclip  # Pour copier dans le presse-papiers
import requests
import yaml  # Pour export YAML
from colorama import Fore, Style, init

init(autoreset=True)

import base64
import binascii
import bz2
import codecs
import csv
import datetime
import gzip
import hashlib
import heapq
import hmac
import json
import logging
import lzma
import os
import pickle
import quopri
import random
import secrets
import smtplib
import string
import urllib.parse
import zlib
from collections import Counter, defaultdict
from email.header import Header, decode_header
from email.mime.text import MIMEText

import bcrypt
import brotli
import lz4.frame
import numpy as np
import requests
import snappy
import zstandard as zstd
from auth_manager import AuthManager
from config_manager import ConfigManager
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from encryption_manager import EncryptionManager
from evaluation_password import EvaluationPassword
from master_password_manager import MasterPasswordManager
from passlib.context import CryptContext
from password_generator import PasswordGenerator
from report_manager import ReportManager
from session_manager import SessionManager
from storage_manager import StorageManager


class MainMenu:

    def __init__(self):

        self.passgen = PasswordGenerator()
        self.session = SessionManager()
        self.report = ReportManager()
        self.eval = EvaluationPassword()
        self.storage = StorageManager()
        self.enc = EncryptionManager()
        self.auth = AuthManager()
        self.conf = ConfigManager()
        self.master_manager = MasterPasswordManager(self.conf.secure_directory)
        self.main = MainMenu()
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

    def main_menu(self):

        # Authentification au lancement
        if not self.master_manager.is_master_password_set():
            self.master_manager.set_master_password()
        master_pwd = self.master_manager.verify_master_password()
        if not master_pwd:
            print("Authentification échouée. Fermeture du programme.")
            exit()

        self.passgen.storage.master_password = master_pwd

        while True:

            if self.session.check_timeout():

                self.auth._master_plaintext = None
                print(Fore.YELLOW + "Session inactive. Veuillez vous ré-authentifier.")

            self.session.update_activity()
            print(Style.BRIGHT + Fore.BLUE + "\n=== KeyChain Manager ===")
            print(
                f"Utilisateur actif : {self.auth.user.current_user['username']} (rôle: {self.user.current_user['role']})"
            )
            options = [
                "Générer un mot de passe",
                "Copier un mot de passe dans le presse-papiers",
                "Consulter l'historique de création",
                "Encoder une chaîne",
                "Décoder une chaîne",
                "Évaluer la force d'un mot de passe",
                "Changer le mot de passe maître",
                "Analyser les mots de passe enregistrés",
                "Rappel de mise à jour",
                "Supprimer les mots de passe expirés",
                "Supprimer les mots de passe compromis",
                "Exporter (chiffré)",
                "Exporter vers CSV",
                "Exporter vers YAML",
                "Importer CSV",
                "Organiser par catégorie",
                "Rechercher un mot de passe",
                "Générer à partir d'un modèle",
                "Estimer le temps de cassage",
                "Générer un QR code",
                "Envoyer une alerte",
                "Changer d'utilisateur",
                "Activer/Désactiver la 2FA",
                "Sauvegarde Cloud",
                "Rapport détaillé",
                "Vérification automatique des fuites",
                "Analyser et évaluer les mots de passe",
                "Quitter",
            ]

            for i, opt in enumerate(options, 1):

                print(f"{i} - {opt}")

            choice = self.get_valid_option("Votre choix : ", range(1, len(options) + 1))

            if choice == 1:

                self.passgen
            elif choice == 2:

                idx = int(input("Entrez l'index du mot de passe à copier : "))
                pwd = self.storage.reveal_password(
                    "passwords.txt", idx, self.enc, self.auth
                )

                if pwd:

                    self.copy_to_clipboard(pwd)

            elif choice == 3:

                self.view_passwords_last_30_days()

            elif choice == 4:

                self.enc.generic_encode()

            elif choice == 5:

                self.enc.generic_encode()

            elif choice == 6:

                self.evaluate_password_menu()

            elif choice == 7:

                self.auth.change_master_password()

            elif choice == 8:

                self.report.analyze_saved_passwords(self.storage, self.enc, self.auth)

            elif choice == 9:

                result = (
                    self.report.remind_password_update(self.password_history)
                    if hasattr(self.report, "remind_password_update")
                    else None
                )
                if result:

                    email, msg = result
                    self.email_sender.send_email(email, "Rappel mise à jour", msg)

            elif choice == 10:

                self.storage.delete_expired_passwords("passwords.txt")

            elif choice == 11:

                self.storage.delete_expired_passwords("passwords.txt")

            elif choice == 12:

                path = input("Chemin d'export chiffré : ").strip()
                self.storage.export_passwords(path)

            elif choice == 13:

                path = input("Chemin d'export CSV : ").strip()
                self.storage.export_passwords_to_csv(path)

            elif choice == 14:

                path = input("Chemin d'export YAML : ").strip()
                self.storage.export_to_yaml(path)

            elif choice == 15:

                path = input("Chemin du CSV à importer : ").strip()
                self.import_passwords_from_csv(path)

            elif choice == 16:

                records = self.storage.load_passwords(
                    os.path.join(self.storage.secure_directory, "passwords.txt")
                )
                organized = defaultdict(list)

                for r in records:

                    organized[r.get("category", "Uncategorized")].append(r)
                print(json.dumps(organized, indent=4))

            elif choice == 17:

                keyword = input("Mot-clé de recherche : ").strip()
                self.search_password(keyword)

            elif choice == 18:

                pattern = input("Modèle (ex: AA-9999-@@) : ").strip()
                pwd = self.generator.generate_password_from_pattern(pattern)
                print(Fore.CYAN + f"Mot de passe généré : {pwd}")

            elif choice == 19:

                pwd = input("Mot de passe à évaluer : ").strip()
                time_est = self.report.estimate_crack_time(pwd)
                print(Fore.CYAN + f"Temps estimé : {time_est}")

            elif choice == 20:

                pwd = input("Mot de passe pour QR code : ").strip()
                self.generate_qr_code(pwd)

            elif choice == 21:

                email = input("Adresse e-mail pour alerte : ").strip()
                msg = input("Message d'alerte : ").strip()
                self.email_sender.send_email(email, "Alerte KeyChain", msg)

            elif choice == 22:

                self.user.switch_user()

            elif choice == 23:

                if self.auth.twofa_enabled:
                    self.auth.twofa_enabled = False
                    print("2FA désactivé.")

                else:

                    self.auth.setup_twofa(self.user.current_user["username"])

            elif choice == 24:

                self.cloud.cloud_backup(self.storage)

            elif choice == 25:

                self.report.generate_detailed_report(self.storage, self.enc, self.auth)

            elif choice == 26:

                result = self.report.auto_breach_check(
                    self.storage, self.enc, self.auth
                )

                if result:

                    email, msg = result
                    self.email_sender.send_email(email, "Alerte Fuites", msg)

            elif choice == 27:

                print(Fore.GREEN + "Au revoir!")
                exit()
            else:

                print("Option invalide.")

    def get_valid_option(self, prompt, options):
        """
        Valide l'entrée utilisateur pour une option de menu.

        Parameters:
        prompt (str): Message à afficher à l'utilisateur.
        options (list): Liste des options valides.

        Returns:
        int: Option choisie par l'utilisateur.
        """
        while True:
            try:
                choice = int(input(prompt))
                if choice in options:
                    return choice
                else:
                    print("Option invalide. Veuillez réessayer.")
            except ValueError:
                print("Veuillez entrer une option valide.")


if __name__ == "__main__":

    MainMenu().main_menu()


# Removed unnecessary backticks and corrected formatting
