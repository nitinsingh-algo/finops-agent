from __future__ import annotations

from cryptography.fernet import Fernet

from algo_finops.agents.iac.adapters.tokens import FernetCipher


def test_cipher_round_trip() -> None:
    cipher = FernetCipher(Fernet.generate_key().decode("utf-8"))
    token = "ghs_super_secret"
    assert cipher.decrypt(cipher.encrypt(token)) == token
    assert token not in cipher.encrypt(token)
