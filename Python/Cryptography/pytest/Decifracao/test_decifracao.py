import pytest
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Benchmarking pytest - Decifração RSA - Cryptography

# Teste de decifração
@pytest.mark.parametrize("key_size", [2048, 4096])
@pytest.mark.parametrize("iterations", [10, 100, 1000, 10000])
def test_decrypt(benchmark, measure, rsa_keys, key_size, iterations):
    private_key, public_key = rsa_keys[key_size]
    message = os.urandom(190)
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Objeto de padding construido uma vez, fora do cronometro (Filosofia A):
    # isola a operacao criptografica, sem reconstruir OAEP/MGF1/SHA256 por chamada.
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

    def _decrypt():
        return private_key.decrypt(ciphertext, oaep)

    result = benchmark.pedantic(_decrypt, iterations=iterations, rounds=15)
    assert result is not None

    metrics = measure(_decrypt)
    benchmark.extra_info["memory_peak_kb"] = metrics["memory_peak_kb"]
    benchmark.extra_info["cpu_time_s"] = metrics["cpu_time_s"]
