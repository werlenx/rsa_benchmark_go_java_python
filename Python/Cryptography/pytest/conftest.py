import os
import pytest
import psutil
from cryptography.hazmat.primitives.asymmetric import rsa


def reset_peak_rss():
    # Zera o high-water mark de RSS do processo (Linux)
    with open("/proc/self/clear_refs", "w") as f:
        f.write("5")


def peak_rss_kb():
    # Pico de memoria fisica residente (VmHWM) em KB, medido pelo SO;
    # instrumento padronizado entre Python, Java e Go
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmHWM:"):
                return float(line.split()[1])
    return 0.0


@pytest.fixture(scope="session")
def rsa_keys():
    result = {}
    for key_size in [2048, 4096]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        result[key_size] = (private_key, private_key.public_key())
    return result


@pytest.fixture
def measure():
    def _measure(fn):
        proc = psutil.Process(os.getpid())
        cpu_before = proc.cpu_times()
        reset_peak_rss()

        fn()

        peak_kb = peak_rss_kb()
        cpu_after = proc.cpu_times()

        # Atencao: CPU medida em UMA chamada e quantizada pela resolucao do
        # relogio (CLK_TCK=100Hz -> 10ms). Para cifra/decifra (dezenas a
        # centenas de us) isso colapsa para 0 ou um tick espurio. A CPU
        # confiavel dessas ops vem da camada vanilla (acumula N e divide).
        cpu_delta = (cpu_after.user - cpu_before.user) + \
                    (cpu_after.system - cpu_before.system)
        return {
            "memory_peak_kb": peak_kb,
            "cpu_time_s": cpu_delta,
        }
    return _measure
