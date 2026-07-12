import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

# Benchmarking pytest - Geração de chaves RSA - Cryptography

# Teste de geração de chaves RSA
@pytest.mark.parametrize("key_size", [2048, 4096])
@pytest.mark.parametrize("iterations", [5, 10, 50, 100])
def test_key_generation(benchmark, measure, key_size, iterations):
    def generate_key():
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    result = benchmark.pedantic(generate_key, iterations=iterations, rounds=15)
    assert result is not None

    metrics = measure(generate_key)
    benchmark.extra_info["memory_peak_kb"] = metrics["memory_peak_kb"]
    benchmark.extra_info["cpu_time_s"] = metrics["cpu_time_s"]
