import os
import unittest
from unittest.mock import mock_open, patch

from config_manager import ConfigManager
from encryption_manager import EncryptionManager
from master_password_manager import MasterPasswordManager
from password_generator import PasswordGenerator

# On suppose que les modules sont dans le PYTHONPATH ou ajoutés par sys.path.append si besoin


class TestPasswordGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = PasswordGenerator()

    def test_generate_password(self):
        password = self.generator.generate_password(
            length=12, use_upper=True, use_lower=True, use_digits=True, use_special=True
        )
        self.assertEqual(len(password), 12)
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(c in "!@#$%^&*()_+-=[]{}|;':,.<>?/" for c in password))


class TestEncryptionManager(unittest.TestCase):
    def setUp(self):
        self.enc = EncryptionManager()

    def test_hash_password(self):
        password = "testpassword"
        hashed = self.enc.hash_password(password)
        self.assertNotEqual(password, hashed)
        self.assertTrue(
            hashed.startswith("$2b$")
            or hashed.startswith("$argon2")
            or hashed.startswith("$pbkdf2")
        )

    def test_derive_key_from_master_password(self):
        master_password = "masterpassword"
        salt = b"random_salt"
        key = self.enc.derive_key_from_master_password(
            master_password, salt, key_length=16
        )
        self.assertEqual(len(key), 16)

    def test_encrypt_decrypt_password(self):
        password = "mypassword"
        key = b"1234567890abcdef"
        encrypted_password, nonce, tag = self.enc.encrypt_password(password, key)
        decrypted_password = self.enc.decrypt_password(
            encrypted_password, key, nonce, tag
        )
        self.assertEqual(password, decrypted_password)


class TestPasswordCriteria(unittest.TestCase):
    def setUp(self):
        self.generator = PasswordGenerator()

    def test_validate_password_criteria(self):
        # Supposons que la méthode s'appelle validate_password_criteria dans PasswordGenerator ou un module d'évaluation
        self.assertTrue(
            self.generator.validate_password_criteria(12, True, True, True, True)
        )
        self.assertFalse(
            self.generator.validate_password_criteria(0, True, True, True, True)
        )
        self.assertFalse(
            self.generator.validate_password_criteria(12, False, False, False, False)
        )


class TestConfigManager(unittest.TestCase):
    def setUp(self):
        self.conf = ConfigManager()

    @patch("builtins.open", new_callable=mock_open, read_data="123456\npassword\n")
    def test_fetch_common_patterns(self, mock_file):
        # Méthode supposée fetch_common_patterns
        patterns = self.conf.fetch_common_patterns("common_patterns.txt")
        self.assertEqual(patterns, ["123456", "password"])


class TestMasterPasswordManager(unittest.TestCase):
    def setUp(self):
        # Utiliser un dossier temporaire pour ne pas toucher aux données réelles
        self.secure_dir = os.path.abspath(".")
        self.manager = MasterPasswordManager(self.secure_dir)
        self.manager._master_hash = self.manager.pwd_context.hash(
            "masterpassword"
        )  # simule un hash déjà présent

    @patch("getpass.getpass", side_effect=["masterpassword"])
    def test_verify_master_password(self, mock_getpass):
        result = self.manager.verify_master_password()
        self.assertEqual(result, "masterpassword")

    @patch("getpass.getpass", side_effect=["wrongpass", "masterpassword"])
    def test_verify_master_password_retry(self, mock_getpass):
        result = self.manager.verify_master_password()
        self.assertEqual(result, "masterpassword")


if __name__ == "__main__":
    unittest.main()
