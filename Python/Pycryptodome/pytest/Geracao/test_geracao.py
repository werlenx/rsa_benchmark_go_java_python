import pytest
from Crypto.PublicKey import RSA

# Benchmarking pytest - Geração de chaves RSA - Pycryptodome

# Teste de geração de chaves RSA
@pytest.mark.parametrize("key_size", [2048, 4096])
@pytest.mark.parametrize("iterations", [5, 10, 50, 100])
def test_key_generation(benchmark, measure, key_size, iterations):
    def generate_key():
        return RSA.generate(key_size)

    result = benchmark.pedantic(generate_key, iterations=iterations, rounds=15)
    assert result is not None

    metrics = measure(generate_key)
    benchmark.extra_info["memory_peak_kb"] = metrics["memory_peak_kb"]
    benchmark.extra_info["cpu_time_s"] = metrics["cpu_time_s"]
