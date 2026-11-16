import os
import unittest
from unittest.mock import patch

from rapid7_freshservice_sync.secrets import (
    AzureKeyVaultSecretProvider,
    EnvSecretProvider,
    default_secret_name,
    validate_key_vault_url,
)


class SecretTests(unittest.TestCase):
    def test_env_provider_reads_required_secret(self) -> None:
        with patch.dict(os.environ, {"FRESHSERVICE_API_KEY": " key "}, clear=True):
            self.assertEqual(EnvSecretProvider().get_required("FRESHSERVICE_API_KEY"), "key")

    def test_env_provider_fails_without_secret(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                EnvSecretProvider().get_required("FRESHSERVICE_API_KEY")

    def test_default_secret_names_match_source(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                default_secret_name("env", "FRESHSERVICE_API_KEY", "freshservice-api-key"),
                "FRESHSERVICE_API_KEY",
            )
            self.assertEqual(
                default_secret_name("azure-keyvault", "FRESHSERVICE_API_KEY", "freshservice-api-key"),
                "freshservice-api-key",
            )

    def test_default_secret_name_can_be_overridden_by_env(self) -> None:
        with patch.dict(os.environ, {"FRESHSERVICE_API_KEY_SECRET": "custom-name"}, clear=True):
            self.assertEqual(
                default_secret_name(
                    "azure-keyvault", "FRESHSERVICE_API_KEY", "freshservice-api-key"
                ),
                "custom-name",
            )

    def test_azure_provider_requires_key_vault_url(self) -> None:
        with self.assertRaises(SystemExit):
            AzureKeyVaultSecretProvider("http://example.com")

    def test_validate_key_vault_url_accepts_https_vault_host(self) -> None:
        self.assertEqual(
            validate_key_vault_url(" https://example.vault.azure.net/ "),
            "https://example.vault.azure.net",
        )

    def test_validate_key_vault_url_rejects_lookalike_hosts(self) -> None:
        invalid_urls = [
            "https://example.vault.azure.net.evil.test",
            "https://vault.azure.net",
            "https://example.vault.azure.net/path",
            "https://example.vault.azure.net?secret=value",
            "https://user@example.vault.azure.net",
        ]
        for invalid_url in invalid_urls:
            with self.subTest(invalid_url=invalid_url):
                with self.assertRaises(SystemExit):
                    validate_key_vault_url(invalid_url)

    def test_azure_provider_rejects_blank_secret_name(self) -> None:
        provider = object.__new__(AzureKeyVaultSecretProvider)
        with self.assertRaises(SystemExit):
            provider.get_required(" ")

if __name__ == "__main__":
    unittest.main()
