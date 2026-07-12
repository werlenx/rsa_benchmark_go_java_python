import pytest
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Benchmarking pytest - Cifração RSA - Cryptography

# Teste de cifração
@pytest.mark.parametrize("key_size", [2048, 4096])
@pytest.mark.parametrize("iterations", [10, 100, 1000, 10000])
def test_encrypt(benchmark, measure, rsa_keys, key_size, iterations):
    private_key, public_key = rsa_keys[key_size]
    message = os.urandom(190)

    # Objeto de padding construido uma vez, fora do cronometro (Filosofia A):
    # isola a operacao criptografica, sem reconstruir OAEP/MGF1/SHA256 por chamada.
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

    def _encrypt():
        return public_key.encrypt(message, oaep)

    result = benchmark.pedantic(_encrypt, iterations=iterations, rounds=15)
    assert result is not None

    metrics = measure(_encrypt)
    benchmark.extra_info["memory_peak_kb"] = metrics["memory_peak_kb"]
    benchmark.extra_info["cpu_time_s"] = metrics["cpu_time_s"]
