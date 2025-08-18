import os, json, csv, gzip, zlib, base64, binascii, codecs, random, string, hashlib, hmac, logging, datetime, smtplib, time, requests
from collections import defaultdict, Counter
from email.mime.text import MIMEText
from getpass import getpass

#import pyotp
#import pyperclip  # Pour copier dans le presse-papiers
import yaml       # Pour export YAML

from colorama import init, Fore, Style
init(autoreset=True)

#from Crypto.Cipher import AES
#from Crypto.Random import get_random_bytes
#from Crypto.Hash import SHA256
#from Crypto.Protocol.KDF import PBKDF2

#from passlib.context import CryptContext
import secrets
import heapq
import lzma
import bz2
#import snappy
import lz4.frame
import zstandard as zstd
import brotli
import quopri
from email.header import Header, decode_header
import numpy as np

from session_manager import SessionManager
from report_manager import ReportManager
from password_generator import PasswordGenerator
from evaluation_password import EvaluationPassword
from storage_manager import StorageManager
from encryption_manager import EncryptionManager
from auth_manager import AuthManager
from config_manager import ConfigManager
class AuthManager():
    
    def __init__(self):
        
        self.conf = ConfigManager()
        self.passgen = PasswordGenerator()
        self.session = SessionManager()
        self.report = ReportManager()
        self.eval = EvaluationPassword()
        self.storage = StorageManager()
        self.enc = EncryptionManager()
        self.auth = AuthManager()
        

        # Méthode importée depuis user_management.py
    def switch_user(self, username):
        """
        Change l'utilisateur actif.
        """
        user_directory = os.path.join("users", username)
        if not os.path.exists(user_directory):
            os.makedirs(user_directory)
        print(f"Utilisateur actif : {username}")
        return user_directory
    
    
    def authenticate_master_password_once(self):
        """
        Authentifie l'utilisateur une seule fois en vérifiant le mot de passe maître.
        La clé dérivée est stockée globalement pour éviter de redemander le mot de passe.

        Returns:
        bool: True si l'authentification réussit, False sinon.
        """
        # Utilisation de MasterPasswordManager pour la gestion du mot de passe maître
        from master_password_manager import MasterPasswordManager
        master_manager = MasterPasswordManager(self.conf.secure_directory)
        if not master_manager.is_master_password_set():
            print("Le mot de passe maître n'est pas défini. Veuillez le définir avant de continuer.")
            return False

        if hasattr(self, "derived_master_key") and self.derived_master_key is not None:
            return True  # Déjà authentifié

        entered_password = input("Entrez votre mot de passe maître pour continuer : ").strip()
        if master_manager.pwd_context.verify(entered_password, master_manager.get_master_hash()):
            self.derived_master_key = self.enc.derive_key_from_master_password(entered_password, b"auth_salt", key_length=16)
            return True
        else:
            print("Mot de passe maître incorrect.")
            return False