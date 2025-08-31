import base64
import getpass
import hashlib
import json
import os

from passlib.context import CryptContext


class MasterPasswordManager:
    def __init__(self, secure_directory):
        self.secure_directory = secure_directory
        self.pwd_context = CryptContext(
            schemes=["bcrypt", "argon2", "pbkdf2_sha256"], deprecated="auto"
        )
        self.master_file = os.path.join(self.secure_directory, "master_password.json")
        self._master_hash = None
        self._load_master_hash()

    def _load_master_hash(self):
        if os.path.exists(self.master_file):
            with open(self.master_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self._master_hash = data.get("hash")
        else:
            self._master_hash = None

    def is_master_password_set(self):
        return self._master_hash is not None

    def set_master_password(self):
        while True:
            pwd1 = getpass.getpass("Définissez un mot de passe maître : ")
            pwd2 = getpass.getpass("Confirmez le mot de passe maître : ")
            if pwd1 != pwd2:
                print("Les mots de passe ne correspondent pas. Réessayez.")
            elif len(pwd1) < 12:
                print("Le mot de passe maître doit contenir au moins 12 caractères.")
            else:
                break
        hash_ = self.pwd_context.hash(pwd1)
        with open(self.master_file, "w", encoding="utf-8") as f:
            json.dump({"hash": hash_}, f)
        self._master_hash = hash_
        print("Mot de passe maître défini avec succès.")

    def verify_master_password(
        self, prompt="Entrez votre mot de passe maître : ", max_attempts=5
    ):
        for attempt in range(max_attempts):
            pwd = getpass.getpass(prompt)
            if self.pwd_context.verify(pwd, self._master_hash):
                return pwd
            else:
                print("Mot de passe incorrect.")
        print("Trop d'échecs. Accès verrouillé temporairement.")
        return None

    def change_master_password(self):

        print("Changement du mot de passe maître.")
        old_pwd = self.verify_master_password("Entrez l'ancien mot de passe maître : ")
        if not old_pwd:
            print("Échec de l'authentification.")
            return False
        while True:
            new_pwd1 = getpass.getpass("Nouveau mot de passe maître : ")
            new_pwd2 = getpass.getpass("Confirmez le nouveau mot de passe maître : ")
            if new_pwd1 != new_pwd2:
                print("Les mots de passe ne correspondent pas.")
            elif len(new_pwd1) < 12:
                print("Le mot de passe maître doit contenir au moins 12 caractères.")
            else:
                break
        hash_ = self.pwd_context.hash(new_pwd1)
        with open(self.master_file, "w", encoding="utf-8") as f:
            json.dump({"hash": hash_}, f)
        self._master_hash = hash_
        print("Mot de passe maître changé avec succès.")
        return True

    def get_master_hash(self):
        return self._master_hash
