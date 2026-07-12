# Benchmark RSA — Python

Implementação do benchmark RSA em Python, comparando duas bibliotecas criptográficas:
[Cryptography](https://cryptography.io/) e [Pycryptodome](https://pycryptodome.readthedocs.io/).

## Organização

```
Python/
├── Cryptography/
│   ├── pytest/
│   │   ├── conftest.py          # fixtures rsa_keys (session) e measure (function)
│   │   ├── Cifracao/test_cifracao.py
│   │   ├── Decifracao/test_decifracao.py
│   │   └── Geracao/test_geracao_chaves.py
│   └── vanilla/sem_pytest.py    # benchmark manual sem framework
├── Pycryptodome/
│   ├── pytest/
│   │   ├── conftest.py
│   │   ├── Cifracao/test_cifracao.py
│   │   ├── Decifracao/test_decifracao.py
│   │   └── Geracao/test_geracao.py
│   └── vanilla/sem_pytest.py
├── requirements.txt
└── venv/
```

## Justificativa das ferramentas

### Framework: pytest-benchmark

`pytest-benchmark` foi escolhido como framework principal pelos seguintes motivos:

- **Modo pedantic**: permite controle explícito de `iterations` e `rounds`, separando o número de chamadas por round da quantidade de rounds estatísticos — o que é fundamental para comparar operações com ordens de grandeza muito diferentes (geração de chave vs cifração).
- **Estatísticas completas**: coleta automaticamente mínimo, máximo, média, mediana, desvio padrão e IQR por benchmark, sem código adicional.
- **`benchmark.extra_info`**: campo nativo para registrar métricas customizadas (memória, CPU) junto ao resultado, incluídas no relatório JSON final.
- **Integração com pytest**: herda parametrização (`@pytest.mark.parametrize`), fixtures e o sistema de relatórios do pytest.

Alternativas consideradas e descartadas:
- **`timeit` puro**: não oferece rounds estatísticos nem saída estruturada — requer implementação manual de toda a infraestrutura de coleta.
- **`memory-profiler`**: instrumenta linha a linha, introduzindo overhead não representativo para microbenchmarks de operações criptográficas.

### Métricas adicionais

| Métrica | Ferramenta | Justificativa |
|---|---|---|
| Memória (pico KB) | Peak RSS (`VmHWM` de `/proc/self/status`, zerado via `/proc/self/clear_refs`) | Pico de memória física residente do processo, medido pelo SO; mesmo instrumento em Python, Java e Go — comparável entre linguagens (inclui a memória basal do runtime) |
| CPU (s) | `psutil` | Lê delta de tempo de CPU do processo (user + system); cross-platform; mais preciso que `resource` para deltas |

### Fixture `scope="session"`

As chaves RSA são geradas uma única vez por sessão de teste e reutilizadas em todos os benchmarks. Isso isola o custo de geração de chave (~50 ms para 2048 bits, ~500 ms para 4096 bits) das medições de cifração e decifração, refletindo o uso real em sistemas de produção onde chaves são persistidas.

### Escala de iterações adaptativa

| Operação | Iterações | Razão |
|---|---|---|
| Geração de chave | `[5, 10, 50, 100]` | Custo ~50–500 ms/chamada; N=10000 seria inviável (~2h) |
| Cifração | `[10, 100, 1000, 10000]` | Custo ~0,5 ms/chamada; N=10000 leva ~75 s |
| Decifração | `[10, 100, 1000, 10000]` | Custo ~1,5 ms/chamada |

## Instalação

```bash
cd Python
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Uso

### Benchmark com pytest-benchmark

```bash
# Exportar resultados em JSON (inclui extra_info com memória e CPU)
pytest Cryptography/pytest/ --benchmark-json=results_cryptography.json -v
pytest Pycryptodome/pytest/ --benchmark-json=results_pycryptodome.json -v

# Operação específica
pytest Cryptography/pytest/Cifracao/ --benchmark-json=results_cifracao.json -v
```

### Benchmark vanilla

```bash
python3 Cryptography/vanilla/sem_pytest.py
python3 Pycryptodome/vanilla/sem_pytest.py
```

## Exportar para CSV

```python
import json, csv

with open('results_cryptography.json') as f:
    data = json.load(f)

with open('results_cryptography.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow([
        'Name', 'Min (s)', 'Max (s)', 'Mean (s)', 'StdDev (s)',
        'Median (s)', 'IQR (s)', 'Rounds', 'Iterations',
        'Memory Peak (KB)', 'CPU Time (s)'
    ])
    for b in data['benchmarks']:
        stats = b['stats']
        extra = b.get('extra_info', {})
        writer.writerow([
            b['name'],
            stats['min'], stats['max'], stats['mean'], stats['stddev'],
            stats['median'], stats['iqr'], stats['rounds'], stats['iterations'],
            extra.get('memory_peak_kb', 0), extra.get('cpu_time_s', 0),
        ])
```
