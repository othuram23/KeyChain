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

import requests
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
from Crypto.Random import get_random_bytes
from encryption_manager import EncryptionManager
from evaluation_password import EvaluationPassword
from master_password_manager import MasterPasswordManager
from passlib.context import CryptContext
from password_generator import PasswordGenerator
from report_manager import ReportManager
from session_manager import SessionManager
from storage_manager import StorageManager


# ----------------- Password Generator -----------------
class ConfigManager:

    def __init__(self):

        self.passgen = PasswordGenerator()
        self.session = SessionManager()
        self.report = ReportManager()
        self.eval = EvaluationPassword()
        self.storage = StorageManager()
        self.enc = EncryptionManager()
        self.auth = AuthManager()
        self.master_manager = MasterPasswordManager(self.load_secure_directory())
        self.master_password = None
        self.password_history = []
        self.secure_directory = self.load_secure_directory()
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

    def load_secure_directory(self):
        """
        Charge le chemin du répertoire sécurisé à partir du fichier de configuration.
        Si le fichier n'existe pas, crée un fichier de configuration par défaut.

        Returns:
        str: Chemin du répertoire sécurisé.
        """
        CONFIG_FILE = os.path.join(os.path.expanduser("~"), "keychain_config.json")
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as config_file:
                config = json.load(config_file)
                return config.get(
                    "secure_directory", os.path.join(os.getcwd(), "secure_data")
                )
        else:
            print("Fichier de configuration introuvable.")
            return self.setup_secure_directory_interactive()

    def setup_secure_directory_interactive(self):
        """
        Configure le répertoire sécurisé en demandant à l'utilisateur de spécifier un chemin.
        Enregistre ce chemin dans le fichier de configuration.

        Returns:
        str: Chemin du répertoire sécurisé.
        """
        CONFIG_FILE = os.path.join(os.path.expanduser("~"), "keychain_config.json")
        print("Veuillez spécifier le chemin du répertoire sécurisé.")
        secure_directory = input(
            "Chemin du répertoire sécurisé (appuyez sur Entrée pour utiliser le répertoire par défaut) : "
        ).strip()
        if not secure_directory:
            secure_directory = os.path.join(os.getcwd(), "secure_data")
        if not os.path.exists(secure_directory):
            os.makedirs(secure_directory, exist_ok=True)
            os.chmod(secure_directory, 0o700)
        with open(CONFIG_FILE, "w", encoding="utf-8") as config_file:
            json.dump({"secure_directory": secure_directory}, config_file, indent=4)
        print(f"Répertoire sécurisé configuré : {secure_directory}")
        return secure_directory

    def fetch_common_patterns(self, common_patterns_path):
        """
        Lit un fichier contenant des mots de passe ou motifs communs pour les vérifier contre les mots de passe générés.

        Parameters:
        common_patterns_path (str): Chemin du fichier contenant les motifs communs.

        Returns:
        list: Liste des mots de passe ou motifs communs. Retourne une liste vide si le fichier est introuvable ou en cas d'erreur.
        """
        try:
            with open(common_patterns_path, "r", encoding="utf-8") as file:
                return file.read().splitlines()
        except FileNotFoundError:
            print(f"Fichier non trouvé : {common_patterns_path}")
            return []
        except Exception as e:
            print(f"Erreur lors de la lecture des motifs communs : {e}")
            return []

    def setup_secure_directory(self):
        """
        Configure un répertoire sécurisé pour stocker les fichiers manipulés par le code.
        Si le répertoire n'existe pas, il est créé avec des permissions restrictives.

        Raises:
        Exception: Si une erreur survient lors de la création ou de la configuration du répertoire.
        """
        try:
            if not os.path.exists(self.secure_directory):
                os.makedirs(self.secure_directory, exist_ok=True)
            os.chmod(
                self.secure_directory, 0o700
            )  # Permissions : lecture/écriture/exécution uniquement pour le propriétaire
        except Exception as e:
            logging.error(
                f"Erreur lors de la configuration du répertoire sécurisé : {e}"
            )
            raise

    def secure_file(self, filepath):
        """
        Restreint les permissions d'un fichier pour qu'il soit accessible uniquement par le propriétaire.

        Parameters:
        filepath (str): Chemin du fichier à sécuriser.

        Raises:
        Exception: Si une erreur survient lors de la modification des permissions.
        """
        try:
            if os.path.exists(filepath):
                os.chmod(
                    filepath, 0o600
                )  # Lecture/écriture uniquement pour le propriétaire
                print(
                    f"Permissions restrictives appliquées pour le fichier : {filepath}"
                )
            else:
                print(f"Fichier introuvable : {filepath}")
        except Exception as e:
            print(f"Erreur lors de la sécurisation du fichier : {e}")
            raise

    def change_directory(self):
        """
        Permet à l'utilisateur de changer le répertoire de travail pour enregistrer les fichiers.

        Returns:
        str: Nouveau répertoire ou répertoire par défaut si aucun changement.
        """
        change_dir = (
            input(
                "Voulez-vous changer de répertoire pour l'enregistrement ? (oui/non) : "
            )
            .strip()
            .lower()
        )
        if change_dir == "oui":
            while True:
                directory = input("Entrez le nouveau répertoire : ").strip()
                if os.path.isdir(directory):
                    try:
                        os.chdir(directory)
                        print(f"Répertoire changé : {os.getcwd()}")
                        return os.getcwd()
                    except PermissionError:
                        print("Permission refusée pour accéder à ce répertoire.")
                else:
                    print("Le répertoire spécifié n'existe pas. Réessayez.")
        default_dir = os.path.expanduser("~")  # Répertoire utilisateur par défaut
        print(f"Répertoire par défaut utilisé : {default_dir}")
        return default_dir

    def ensure_secure_directory_permissions(self):
        os.makedirs(self.secure_directory, exist_ok=True)
        os.chmod(self.secure_directory, 0o700)

    def mask_password(self, password):
        """
        Masque un mot de passe pour l'affichage.

        Parameters:
        password (str): Mot de passe à masquer.

        Returns:
        str: Mot de passe masqué.
        """
        return "*" * len(password)

    def is_online(self):
        """
        Vérifie si une connexion Internet est disponible.
        """
        try:
            requests.get("https://www.google.com", timeout=5)
            return True
        except requests.ConnectionError:
            return False

    def manage_encryption_key(self):
        """
        Gère la clé de chiffrement pour les sauvegardes.

        Returns:
        bytes: Clé de chiffrement.
        """
        key_file = os.path.join(self.secure_directory, "encryption_key.key")
        if not os.path.exists(key_file):
            key = get_random_bytes(16)
            with open(key_file, "wb") as f:
                f.write(key)
            self.secure_file(key_file)
            print("Nouvelle clé de chiffrement générée et sauvegardée.")
        else:
            with open(key_file, "rb") as f:
                key = f.read()
        return key
