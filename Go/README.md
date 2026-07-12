# Benchmark RSA — Go

Implementação do benchmark RSA em Go usando a biblioteca padrão `crypto/rsa`.

## Organização

```
Go/
├── go.mod
├── benchmark_test.go   # benchmark com o framework nativo testing
└── vanilla.go          # benchmark manual sem framework
```

## Justificativa das ferramentas

### Framework: `testing` (stdlib) + `go test -bench`

Go possui benchmarking nativo integrado ao toolchain, sem dependência externa.
O framework é usado como organizador/harness, mas com **iterações fixas** em vez do
`b.N` adaptativo, para espelhar o `benchmark.pedantic(iterations=N, rounds=15)` do
Python e garantir simetria entre as linguagens.

- **Sub-benchmarks parametrizados**: cada operação é dividida em `b.Run("bits=…/iters=…")`,
  varrendo `N ∈ [5,10,50,100]` (geração) e `[10,100,1000,10000]` (cifração/decifração),
  os mesmos conjuntos do Python e do vanilla.
- **15 rounds × N chamadas manuais**: o corpo do sub-benchmark calcula média e desvio
  padrão amostral (÷ rounds-1) sobre 15 rounds, cada um com N chamadas em lote; o tempo
  é reportado por chamada via `b.ReportMetric` (`s/op`, `std-s`).
- **Peak RSS** (`VmHWM` de `/proc/self/status`, zerado via `/proc/self/clear_refs`):
  pico de memória física residente do processo durante o lote (`peak-rss-KB`);
  mesmo instrumento em Python, Java e Go. O pico não é normalizável por chamada.
- **`syscall.Getrusage`**: tempo de CPU do processo (user + system), normalizado por
  chamada (`cpu-s`) — análogo ao `psutil.cpu_times()` do Python.

> **Execução obrigatória com `-benchtime=1x`**: como o controle de iterações é manual,
> essa flag faz o framework invocar o corpo de cada sub-benchmark uma única vez. Sem ela,
> o loop adaptativo de `b.N` reexecutaria o corpo várias vezes desnecessariamente.

Trade-off: forçar iterações fixas abre mão do `b.N` adaptativo (que estabiliza medições
automaticamente). É o preço da simetria cross-language.

Alternativas consideradas:
- **`github.com/cespare/bench`** e similares: oferecem menos controle que o pacote nativo e adicionam dependência externa desnecessária.

### Biblioteca RSA: `crypto/rsa` (stdlib)

Go possui uma única implementação RSA na biblioteca padrão (`crypto/rsa`), utilizando `crypto/rand` como fonte de entropia e `crypto/sha256` para o padding OAEP — equivalente ao `OAEP+SHA256` usado nas versões Python.

### Métricas coletadas

| Métrica | API Go | Descrição |
|---|---|---|
| Tempo médio por chamada | `b.ReportMetric` | `s/op` — média de 15 rounds |
| Desvio padrão amostral | `b.ReportMetric` | `std-s` — entre os 15 rounds (÷ rounds-1) |
| Memória (pico RSS) | `/proc/self/status` (`VmHWM`) | `peak-rss-KB` — pico do processo no lote |
| Tempo de CPU | `syscall.Getrusage` | `cpu-s` — user + system por chamada |

### Chaves geradas uma vez (`init`)

As chaves RSA são geradas no bloco `init()` do arquivo de benchmark, antes de qualquer medição. Isso é equivalente ao `scope="session"` do pytest — garante que o custo de geração de chave não contamina os benchmarks de cifração e decifração.

## Instalação

```bash
# Go 1.21+
go version
```

## Uso

### Benchmark com testing

```bash
# Rodar todos os benchmarks (obrigatório -benchtime=1x; -run=^$ pula os testes)
go test -bench=. -benchtime=1x -run=^$

# Operação específica
go test -bench=BenchmarkEncrypt -benchtime=1x -run=^$

# Exportar para análise
go test -bench=. -benchtime=1x -run=^$ | tee results.txt
```

### Benchmark vanilla

```bash
go run vanilla.go
```

## Saída esperada

```
BenchmarkKeyGen/bits=2048/iters=5-8       1   ...   0.052 s/op   0.0012 std-s   ... peak-rss-KB   ... cpu-s
BenchmarkKeyGen/bits=4096/iters=5-8       1   ...   0.410 s/op   0.0090 std-s   ... peak-rss-KB   ... cpu-s
BenchmarkEncrypt/bits=2048/iters=1000-8   1   ...   0.00045 s/op ...
BenchmarkDecrypt/bits=2048/iters=1000-8   1   ...   0.00130 s/op ...
```
