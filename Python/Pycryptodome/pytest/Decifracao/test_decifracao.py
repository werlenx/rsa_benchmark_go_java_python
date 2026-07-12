import pytest
import os
from Crypto.Cipher import PKCS1_OAEP

# Benchmarking pytest - Decifração RSA - Pycryptodome

# Teste de decifração
@pytest.mark.parametrize("key_size", [2048, 4096])
@pytest.mark.parametrize("iterations", [10, 100, 1000, 10000])
def test_decrypt(benchmark, measure, rsa_keys, key_size, iterations):
    private_key = rsa_keys[key_size]
    public_key = private_key.publickey()
    message = os.urandom(190)
    ciphertext = PKCS1_OAEP.new(public_key).encrypt(message)

    cipher_rsa = PKCS1_OAEP.new(private_key)

    def _decrypt():
        return cipher_rsa.decrypt(ciphertext)

    result = benchmark.pedantic(_decrypt, iterations=iterations, rounds=15)
    assert result is not None

    metrics = measure(_decrypt)
    benchmark.extra_info["memory_peak_kb"] = metrics["memory_peak_kb"]
    benchmark.extra_info["cpu_time_s"] = metrics["cpu_time_s"]
