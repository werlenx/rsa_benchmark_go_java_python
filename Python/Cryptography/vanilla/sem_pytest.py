import os
import timeit
import psutil
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from tabulate import tabulate

# Benchmark vanilla RSA - Cryptography
# Metricas: tempo medio, desvio padrao amostral, pico de memoria (RSS) e tempo de CPU


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


def measure(fn, iterations):
    proc = psutil.Process(os.getpid())
    cpu_before = proc.cpu_times()
    reset_peak_rss()

    times = [timeit.timeit(fn, number=1) for _ in range(iterations)]

    peak_kb = peak_rss_kb()
    cpu_after = proc.cpu_times()

    mean = sum(times) / iterations
    std = (sum((t - mean) ** 2 for t in times) / (iterations - 1)) ** 0.5
    cpu_delta = (cpu_after.user - cpu_before.user) + (cpu_after.system - cpu_before.system)
    return {
        "mean_s": mean,
        "std_s": std,
        "memory_peak_kb": peak_kb,
        "cpu_time_s": cpu_delta / iterations,
    }


KEY_SIZES = [2048, 4096]
GEN_ITERATIONS = [5, 10, 50, 100]
CRYPTO_ITERATIONS = [10, 100, 1000, 10000]

# Gerar chaves uma vez por tamanho (reutilizadas em cifração e decifração)
rsa_keys = {}
for key_size in KEY_SIZES:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    rsa_keys[key_size] = (private_key, private_key.public_key())

table_data = []

# Geração de chave
for key_size in KEY_SIZES:
    for iters in GEN_ITERATIONS:
        def generate_key(ks=key_size):
            return rsa.generate_private_key(public_exponent=65537, key_size=ks)

        m = measure(generate_key, iters)
        table_data.append([
            "Geracao", key_size, iters,
            m["mean_s"], m["std_s"], m["memory_peak_kb"], m["cpu_time_s"],
        ])

# Cifração
for key_size in KEY_SIZES:
    private_key, public_key = rsa_keys[key_size]
    message = os.urandom(190)

    # Padding construido uma vez, fora do cronometro (Filosofia A)
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

    def encrypt(pk=public_key, msg=message, pad=oaep):
        return pk.encrypt(msg, pad)

    for iters in CRYPTO_ITERATIONS:
        m = measure(encrypt, iters)
        table_data.append([
            "Cifracao", key_size, iters,
            m["mean_s"], m["std_s"], m["memory_peak_kb"], m["cpu_time_s"],
        ])

# Decifração
for key_size in KEY_SIZES:
    private_key, public_key = rsa_keys[key_size]
    message = os.urandom(190)
    # Padding construido uma vez, fora do cronometro (Filosofia A)
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    ciphertext = public_key.encrypt(message, oaep)

    def decrypt(priv=private_key, ct=ciphertext, pad=oaep):
        return priv.decrypt(ct, pad)

    for iters in CRYPTO_ITERATIONS:
        m = measure(decrypt, iters)
        table_data.append([
            "Decifracao", key_size, iters,
            m["mean_s"], m["std_s"], m["memory_peak_kb"], m["cpu_time_s"],
        ])

headers = [
    "Operacao", "Chave (bits)", "Iteracoes",
    "Media (s)", "Std (s)", "Pico RSS (KB)", "CPU (s)",
]
print(tabulate(table_data, headers=headers, floatfmt=".9f"))
