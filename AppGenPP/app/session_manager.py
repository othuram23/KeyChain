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
# import pyotp
# import pyperclip  # Pour copier dans le presse-papiers
import yaml  # Pour export YAML
from colorama import Fore, Style, init

init(autoreset=True)

# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from Crypto.Hash import SHA256
# from Crypto.Protocol.KDF import PBKDF2

import bz2
import heapq
import lzma
import quopri
# from passlib.context import CryptContext
import secrets
from email.header import Header, decode_header

import brotli
# import snappy
import lz4.frame
import numpy as np
import zstandard as zstd
from auth_manager import AuthManager
from config_manager import ConfigManager
from encryption_manager import EncryptionManager
from evaluation_password import EvaluationPassword
from master_password_manager import MasterPasswordManager
from password_generator import PasswordGenerator
from report_manager import ReportManager
from storage_manager import StorageManager


class EmailSender:
    def __init__(self, smtp_server, smtp_port, sender_email, sender_password):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password

    def send_email(self, recipient_email, subject, message):
        try:
            msg = MIMEText(message)
            msg["Subject"] = subject
            msg["From"] = self.sender_email
            msg["To"] = recipient_email

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, recipient_email, msg.as_string())
            print(f"E-mail envoyé à {recipient_email}.")
        except Exception as e:
            print(f"Erreur lors de l'envoi de l'e-mail : {e}")


class SessionManager:

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
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            filename=os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "password_manager.log"
            ),
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )

    def send_security_alert(self, email, message):
        """
        Envoie une alerte de sécurité par e-mail.
        """
        try:
            sender_email = "your_email@example.com"
            sender_password = "your_password"
            smtp_server = "smtp.example.com"
            smtp_port = 587

            msg = MIMEText(message)
            msg["Subject"] = "Alerte de sécurité KeyChain"
            msg["From"] = sender_email
            msg["To"] = email

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, email, msg.as_string())
            print(f"Alerte envoyée à {email}.")
        except Exception as e:
            print(f"Erreur lors de l'envoi de l'alerte : {e}")
