import pytest
import os
from Crypto.Cipher import PKCS1_OAEP

# Benchmarking pytest - Cifração RSA - Pycryptodome

# Teste de cifração
@pytest.mark.parametrize("key_size", [2048, 4096])
@pytest.mark.parametrize("iterations", [10, 100, 1000, 10000])
def test_encrypt(benchmark, measure, rsa_keys, key_size, iterations):
    private_key = rsa_keys[key_size]
    public_key = private_key.publickey()
    message = os.urandom(190)
    cipher_rsa = PKCS1_OAEP.new(public_key)

    def _encrypt():
        return cipher_rsa.encrypt(message)

    result = benchmark.pedantic(_encrypt, iterations=iterations, rounds=15)
    assert result is not None

    metrics = measure(_encrypt)
    benchmark.extra_info["memory_peak_kb"] = metrics["memory_peak_kb"]
    benchmark.extra_info["cpu_time_s"] = metrics["cpu_time_s"]
