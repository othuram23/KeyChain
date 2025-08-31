import logging
import os
import random
import string

import numpy as np
from colorama import Fore, Style, init

init(autoreset=True)

import secrets

from auth_manager import AuthManager
from config_manager import ConfigManager
from encryption_manager import EncryptionManager
from evaluation_password import EvaluationPassword
from main import MainMenu
from master_password_manager import MasterPasswordManager
from password_generator import PasswordGenerator
from report_manager import ReportManager
from session_manager import SessionManager
from storage_manager import StorageManager


# ----------------- Password Generator -----------------
class PasswordGenerator:

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
        self.main = MainMenu()

    def setup_logging(self):
        logging.basicConfig(
            filename=os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "password_manager.log"
            ),
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )

    @staticmethod
    def get_ambiguous_chars():
        """
        Retourne un ensemble de caractères considérés comme ambigus ou similaires
        """
        return set("1lI0OoB8S5Z2Q")

    @staticmethod
    def calculate_entropy(password: str, pool_size: int) -> float:
        """
        Calcule l'entropie d'un mot de passe en bits.
        """
        if pool_size <= 1:
            return 0.0
        return len(password) * np.log2(pool_size)

    @staticmethod
    def get_strength_message(entropy: float) -> str:
        """
        Retourne un message informatif selon l'entropie.
        """
        if entropy < 28:
            return Fore.RED + "Très faible : Ce mot de passe est facilement devinable."
        elif entropy < 36:
            return Fore.YELLOW + "Faible : Ce mot de passe est vulnérable aux attaques."
        elif entropy < 60:
            return (
                Fore.CYAN + "Moyen : Ce mot de passe est raisonnable mais améliorable."
            )
        elif entropy < 80:
            return Fore.GREEN + "Fort : Ce mot de passe est robuste."
        else:
            return (
                Fore.GREEN
                + Style.BRIGHT
                + "Très fort : Ce mot de passe est extrêmement robuste."
            )

    @staticmethod
    def generate_password(
        length: int = 12,
        use_upper: bool = True,
        use_lower: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        exclude_ambiguous: bool = False,
    ) -> str:
        """
        Génère un mot de passe aléatoire avec option d'exclusion des caractères ambigus
        """
        if not (use_upper or use_lower or use_digits or use_special):

            raise ValueError("Au moins un type de caractère doit être sélectionné")

        # Définir les ensembles de caractères
        ambiguous_chars = (
            PasswordGenerator.get_ambiguous_chars() if exclude_ambiguous else set()
        )

        upper_chars = (
            "".join(c for c in string.ascii_uppercase if c not in ambiguous_chars)
            if use_upper
            else ""
        )
        lower_chars = (
            "".join(c for c in string.ascii_lowercase if c not in ambiguous_chars)
            if use_lower
            else ""
        )
        digit_chars = (
            "".join(c for c in string.digits if c not in ambiguous_chars)
            if use_digits
            else ""
        )
        special_chars = (
            "".join(c for c in string.punctuation if c not in ambiguous_chars)
            if use_special
            else ""
        )

        required_types = sum(
            [
                bool(upper_chars),
                bool(lower_chars),
                bool(digit_chars),
                bool(special_chars),
            ]
        )

        if length < required_types:
            raise ValueError(
                f"La longueur doit être au moins {required_types} pour inclure chaque type."
            )

        password_chars = []
        if upper_chars:
            password_chars.append(secrets.choice(upper_chars))
        if lower_chars:
            password_chars.append(secrets.choice(lower_chars))
        if digit_chars:
            password_chars.append(secrets.choice(digit_chars))
        if special_chars:
            password_chars.append(secrets.choice(special_chars))

        pool = upper_chars + lower_chars + digit_chars + special_chars

        for _ in range(length - len(password_chars)):
            password_chars.append(secrets.choice(pool))

        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars)

    def generate_password_menu(self):
        begin_with_personal_values: bool = (
            input("\nVoulez-vous utiliser les valeurs par défaut ? (oui/non): ")
            .strip()
            .lower()
            == "non"
        )

        if begin_with_personal_values:
            while True:
                try:
                    length = int(
                        input(
                            "Spécifiez la longueur du mot de passe que vous souhaitez générer: "
                        )
                    )
                    if length <= 0:
                        print("La longueur doit être un entier positif. Réessayez.")
                    else:
                        break
                except ValueError:
                    print("Veuillez entrer un entier valide. Réessayez.")
            use_upper: bool = (
                input(
                    "Voulez-vous que le mot de passe comporte des lettres majuscules ? (oui/non): "
                )
                .strip()
                .lower()
                == "oui"
            )
            use_lower: bool = (
                input(
                    "Voulez-vous que le mot de passe comporte des lettres minuscules ? (oui/non): "
                )
                .strip()
                .lower()
                == "oui"
            )
            use_digits: bool = (
                input(
                    "Voulez-vous que le mot de passe comporte des nombres ? (oui/non): "
                )
                .strip()
                .lower()
                == "oui"
            )
            use_special: bool = (
                input(
                    "Voulez-vous que le mot de passe comporte des caractères spéciaux ? (oui/non): "
                )
                .strip()
                .lower()
                == "oui"
            )
            exclude_ambiguous: bool = (
                input(
                    "Voulez-vous exclure les caractères ambigus (1lI0OoB8S5Z2Q) ? (oui/non): "
                )
                .strip()
                .lower()
                == "oui"
            )

            password: str = self.generate_password(
                length=length,
                use_upper=use_upper,
                use_lower=use_lower,
                use_digits=use_digits,
                use_special=use_special,
                exclude_ambiguous=exclude_ambiguous,
            )
            # Calcul du pool de caractères utilisé
            ambiguous_chars = self.get_ambiguous_chars() if exclude_ambiguous else set()
            pool = ""
            if use_upper:
                pool += "".join(
                    c for c in string.ascii_uppercase if c not in ambiguous_chars
                )
            if use_lower:
                pool += "".join(
                    c for c in string.ascii_lowercase if c not in ambiguous_chars
                )
            if use_digits:
                pool += "".join(c for c in string.digits if c not in ambiguous_chars)
            if use_special:
                pool += "".join(
                    c for c in string.punctuation if c not in ambiguous_chars
                )
        else:
            password = self.generate_password()
            # Par défaut, tous les types sont utilisés sans exclusion
            pool = (
                string.ascii_uppercase
                + string.ascii_lowercase
                + string.digits
                + string.punctuation
            )

        # Calcul et affichage de l'entropie
        entropy = self.calculate_entropy(password, len(set(pool)))
        print(f"\nEntropie du mot de passe : {entropy:.2f} bits")
        print(self.get_strength_message(entropy))

        print(f"\nMot de passe généré: {self.conf.mask_password(password)}")
        logging.info(f"Mot de passe généré: {self.conf.mask_password(password)}")
        print("\nCryptage et sauvegarde des mots de passe sur la machine....")
        self.storage.add_password_to_history(
            password
        )  # Ajout du mot de passe à l'historique

        directory: str = (
            self.conf.change_directory()
        )  # Correction de l'appel de change_directory
        if directory != "C:/Users/Admin/":
            filename: str = input(
                "\nEntrez le nom du fichier où sauvegarder le mot de passe (): "
            ).strip()
            self.storage.save_password_to_file(password=password, filename=filename)
            print("\nMot de passe sauvegardé avec succès!")
        else:
            self.storage.save_password_to_file(
                password=password, filename="passwords.txt"
            )
            print("\nMot de passe sauvegardé avec succès!")

    def change_master_password(self):
        """
        Permet à l'utilisateur de changer le mot de passe maître via MasterPasswordManager.
        """
        self.master_manager.change_master_password()

    @staticmethod
    def generate_password_from_pattern(pattern, exclude_ambiguous=False):
        """
        Génère un mot de passe basé sur un modèle.
        Exemple de modèle : AA-9999-@@ (A = lettre majuscule, 9 = chiffre, @ = caractère spécial)
        Améliorations : validation du motif, exclusion des caractères ambigus, calcul d'entropie.
        """
        # 1. Validation du motif
        supported = {"A", "a", "9", "@"}
        for char in pattern:
            if (
                char not in supported
                and char not in string.punctuation
                and not char.isalnum()
            ):
                raise ValueError(f"Caractère non supporté dans le motif : {char}")

        # 2. Exclusion des caractères ambigus
        ambiguous = (
            PasswordGenerator.get_ambiguous_chars() if exclude_ambiguous else set()
        )
        char_map = {
            "A": "".join(c for c in string.ascii_uppercase if c not in ambiguous),
            "a": "".join(c for c in string.ascii_lowercase if c not in ambiguous),
            "9": "".join(c for c in string.digits if c not in ambiguous),
            "@": "".join(c for c in string.punctuation if c not in ambiguous),
        }
        password = ""
        pool = set()
        for char in pattern:
            if char in char_map:
                choice = random.choice(char_map[char])
                password += choice
                pool.update(char_map[char])
            else:
                password += char
                pool.add(char)
        # 3. Calcul et affichage de l'entropie
        entropy = PasswordGenerator.calculate_entropy(password, len(pool))
        print(f"Entropie du mot de passe généré : {entropy:.2f} bits")
        print(PasswordGenerator.get_strength_message(entropy))
        return password
