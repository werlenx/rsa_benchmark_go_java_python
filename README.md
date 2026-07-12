# Benchmark Comparativo de RSA em Python, Go e Java

Avaliação de desempenho de implementações do algoritmo RSA em múltiplas
linguagens e bibliotecas criptográficas, medindo **tempo de execução**,
**pico de memória (peak RSS)** e **tempo de CPU** para as operações de
geração de chaves, cifração e decifração.

O trabalho estende e corrige a avaliação de Rosa e Campiolo (WTICG/SBSeg
2024), originalmente restrita a Python, incorporando Go e Java, novas
métricas e correções metodológicas.

## Linguagens e ferramentas

| Linguagem | Biblioteca RSA | Framework de benchmark | Vanilla (manual) |
|---|---|---|---|
| Python | `cryptography` (hazmat / OpenSSL) | pytest-benchmark | `timeit` + peak RSS + `psutil` |
| Python | `pycryptodome` | pytest-benchmark | `timeit` + peak RSS + `psutil` |
| Go | `crypto/rsa` (stdlib) | `go test -bench` | `time` + peak RSS + `syscall.Getrusage` |
| Java | `java.security` (JCA) | JMH 1.37 | `System.nanoTime` + peak RSS + `OperatingSystemMXBean` |
| Java | BouncyCastle | JMH 1.37 | `System.nanoTime` + peak RSS + `OperatingSystemMXBean` |

O **peak RSS** é lido do campo `VmHWM` de `/proc/self/status` (Linux) e é
o mesmo instrumento de memória nas três linguagens, permitindo comparação
direta. A cada operação, o contador é zerado via `/proc/self/clear_refs`.

## Operações avaliadas

Preenchimento **OAEP-SHA256**, mensagem de **190 bytes**, **15 rounds**
estatísticos por medição.

| Operação | Chaves | Iterações |
|---|---|---|
| Geração de chave | 2048, 4096 bits | 5, 10, 50, 100 |
| Cifração | 2048, 4096 bits | 10, 100, 1.000, 10.000 |
| Decifração | 2048, 4096 bits | 10, 100, 1.000, 10.000 |

## Estrutura do repositório

```
rsa_benchmark_go_java_python/
├── Python/   # cryptography + pycryptodome (pytest-benchmark + vanilla)
├── Go/       # crypto/rsa stdlib (go test + vanilla)
└── Java/     # java.security + BouncyCastle (JMH + vanilla)
```

Cada pasta contém seu próprio `README.md` com instruções de instalação,
uso e justificativa das ferramentas escolhidas.

## Resultados

Os dados brutos das medições acompanham o repositório (por exemplo,
`Java/resultados/` e os arquivos `results.json` das suítes `pytest`). A
análise completa — tabelas, figuras e discussão — está no artigo que
acompanha este trabalho.
