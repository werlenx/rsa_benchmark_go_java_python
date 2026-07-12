import os
import timeit
import psutil
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from tabulate import tabulate

# Benchmark vanilla RSA - Pycryptodome
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
    rsa_keys[key_size] = RSA.generate(key_size)

table_data = []

# Geração de chave
for key_size in KEY_SIZES:
    for iters in GEN_ITERATIONS:
        def generate_key(ks=key_size):
            return RSA.generate(ks)

        m = measure(generate_key, iters)
        table_data.append([
            "Geracao", key_size, iters,
            m["mean_s"], m["std_s"], m["memory_peak_kb"], m["cpu_time_s"],
        ])

# Cifração
for key_size in KEY_SIZES:
    key = rsa_keys[key_size]
    cipher_rsa = PKCS1_OAEP.new(key.publickey())
    message = os.urandom(190)

    def encrypt(c=cipher_rsa, msg=message):
        return c.encrypt(msg)

    for iters in CRYPTO_ITERATIONS:
        m = measure(encrypt, iters)
        table_data.append([
            "Cifracao", key_size, iters,
            m["mean_s"], m["std_s"], m["memory_peak_kb"], m["cpu_time_s"],
        ])

# Decifração
for key_size in KEY_SIZES:
    key = rsa_keys[key_size]
    message = os.urandom(190)
    ciphertext = PKCS1_OAEP.new(key.publickey()).encrypt(message)
    cipher_rsa = PKCS1_OAEP.new(key)

    def decrypt(c=cipher_rsa, ct=ciphertext):
        return c.decrypt(ct)

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
