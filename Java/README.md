# Benchmark RSA — Java

Implementação do benchmark RSA em Java usando `java.security` (stdlib) para criptografia
e JMH (Java Microbenchmark Harness) como framework de benchmark.

## Organização

```
Java/
├── pom.xml
└── src/main/java/benchmark/
    ├── RsaBenchmark.java     # JMH        — biblioteca java.security (JCA)
    ├── Vanilla.java          # manual     — biblioteca java.security (JCA)
    ├── RsaBenchmarkBC.java   # JMH        — biblioteca BouncyCastle (API lightweight)
    └── VanillaBC.java        # manual     — biblioteca BouncyCastle (API lightweight)
```

Há **duas bibliotecas RSA** avaliadas, espelhando a comparação do Python
(`cryptography` × `pycryptodome`): a nativa `java.security` (JCA) e o **BouncyCastle**.

## Justificativa das ferramentas

### Framework: JMH (Java Microbenchmark Harness)

JMH é o framework padrão de microbenchmarking para a JVM, desenvolvido pela própria
Oracle/OpenJDK. É usado aqui como harness, mas configurado para **iterações fixas**,
espelhando o `benchmark.pedantic(iterations=N, rounds=15)` do Python e garantindo
simetria entre as linguagens.

- **`Mode.SingleShotTime` + `measurementBatchSize = N`**: cada amostra executa N chamadas
  em lote e o JMH reporta o `Score` por chamada (divide pelo `batchSize`). Mapeia
  diretamente o `iterations=N` do `pedantic`.
- **`measurementIterations = 15`**: 15 rounds de medição (o `Cnt` da saída), equivalente
  ao `rounds=15` do `pedantic`; o `Error` reportado é o desvio entre esses rounds.
- **Varredura de N via `OptionsBuilder`**: como `batchSize` é constante de anotação (não
  aceita `@Param`), o `main()` faz um run por valor de N — `[5,10,50,100]` para geração e
  `[10,100,1000,10000]` para cifração/decifração.
- **`@Param`**: parametriza o tamanho de chave (2048/4096), equivalente ao
  `@pytest.mark.parametrize` do Python.
- **`@Setup(Level.Trial)`**: executa o setup uma vez por trial (combinação de parâmetros),
  equivalente ao `scope="session"` — chaves geradas uma vez e reutilizadas nas medições.
- **Isolamento de processo**: cada benchmark roda em um processo JVM separado (`@Fork(1)`).

Trade-off: para fidelidade ao `pedantic`, o warmup é desativado (`warmupIterations(0)`).
Isso reintroduz ruído de JIT nas primeiras amostras — efeito esperado. É o preço de
impor a parametrização do Python a uma ferramenta
projetada para medir o regime estacionário (steady state) após aquecimento.

Alternativas consideradas e descartadas:
- **`System.nanoTime()` manual**: usado na versão vanilla (`Vanilla.java`); sem o harness
  do JMH (isolamento de processo, gestão de estado, batching).
- **Caliper (Google)**: descontinuado.
- **`Mode.AverageTime` com warmup**: regime estacionário idiomático do JMH, mas não permite
  reproduzir a varredura de iterações fixas do `pedantic`.

### Bibliotecas RSA: `java.security` (stdlib) e BouncyCastle

São avaliadas **duas** bibliotecas, espelhando a comparação do Python:

- **`java.security` (JCA)** — RSA-OAEP nativo via `javax.crypto.Cipher` com o algoritmo
  `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`. `KeyPairGenerator` gera o par de chaves.
  (`RsaBenchmark.java`, `Vanilla.java`)
- **BouncyCastle (API lightweight)** — `org.bouncycastle.crypto.*`: `RSAKeyPairGenerator`
  para a chave e `OAEPEncoding` sobre `RSAEngine` com `SHA256Digest` no hash **e** no MGF1.
  É uma API genuinamente distinta da JCA (não passa pelo JCE), análoga à diferença entre
  `cryptography` e `pycryptodome` no Python. (`RsaBenchmarkBC.java`, `VanillaBC.java`)

Dependência: `org.bouncycastle:bcprov-jdk18on`. Como esse JAR é assinado, o
`maven-shade-plugin` remove `META-INF/*.SF/.DSA/.RSA` no empacotamento (senão o fat JAR
falha com *"Invalid signature file digest"*).

> **Nota de comparabilidade:** a versão `java.security` usa, por omissão, MGF1-**SHA-1**
> (a transformação não recebe `OAEPParameterSpec`), enquanto Python, Go e a versão
> BouncyCastle usam MGF1-**SHA-256**. Uniformizar isso fica como trabalho futuro.

### Métricas coletadas

| Métrica | API Java | Descrição |
|---|---|---|
| Tempo médio por chamada | JMH `Mode.SingleShotTime` + `batchSize` | `Score` em ms/op (média de 15 rounds) |
| Desvio entre rounds | JMH `Error` | `± Error` sobre os 15 rounds de medição |
| Tempo de CPU por chamada | `OperatingSystemMXBean.getProcessCpuTime()` | Tabela `CPU (s)` impressa fora do JMH (`measureCpuPass`) |

O JMH mede apenas tempo (como todo framework de benchmark). A CPU é coletada por uma
passada separada no `main()`, fora do JMH — exatamente como o Python coleta CPU via
`psutil` fora do pytest-benchmark. A memória é medida na camada vanilla
(`Vanilla.java`/`VanillaBC.java`) via peak RSS (`VmHWM` de `/proc/self/status`,
zerado via `/proc/self/clear_refs`) — o mesmo instrumento usado em Python e Go,
o que torna os valores comparáveis entre linguagens.

### Gerenciamento de build: Maven

Maven foi escolhido por:
- Gerenciamento simples de dependência JMH (`pom.xml`)
- `maven-shade-plugin` gera um fat JAR executável (`benchmarks.jar`) com todas as
  dependências — padrão recomendado pelo JMH
- `exec-maven-plugin` permite executar o Vanilla diretamente sem empacotar

## Instalação

```bash
# Java 17+ e Maven 3.6+ (o código usa records, exigem Java 16+)
java -version
mvn -version
```

## Uso

### Benchmark com JMH

Cada classe de benchmark tem seu próprio `main()`, que varre os valores de N (um run por
valor) via `OptionsBuilder`. Não passe argumentos de seleção — a varredura é programática.
Roda-se **cada biblioteca separadamente**, como no Python.

**Benchmark completo** = todas as operações (geração, cifração, decifração) × tamanhos
(2048, 4096) × todos os valores de N, com 15 rounds cada. Para coletar os dados do
trabalho, rode os quatro comandos abaixo (cada um cobre uma biblioteca/abordagem):

```bash
# Compilar e empacotar (gera target/benchmarks.jar)
mvn clean package

# --- Com biblioteca de benchmark (JMH) ---
java -jar target/benchmarks.jar                          # java.security
java -cp target/benchmarks.jar benchmark.RsaBenchmarkBC  # BouncyCastle

# --- Sem biblioteca (vanilla) ---
mvn compile exec:java -Dexec.mainClass="benchmark.Vanilla"     # java.security
mvn compile exec:java -Dexec.mainClass="benchmark.VanillaBC"   # BouncyCastle
```

Para guardar a saída em arquivo (recomendado para análise posterior):

```bash
java -cp target/benchmarks.jar benchmark.RsaBenchmarkBC | tee resultados_bc.txt
```

> **Atenção à duração.** O benchmark completo é demorado: a geração de chave 4096 com
> N=100 executa 100 gerações (~minutos), e a cifração/decifração com N=10000 executa
> 10.000 chamadas por amostra. O run completo pode levar de vários minutos a horas
> (especialmente a geração 4096). Reserve tempo e evite uso concorrente da máquina.

**Smoke test rápido** (validar que tudo roda, sem esperar o run inteiro) — usa o JMH
diretamente com 1 round e N pequeno, apenas cifração/decifração em 2048 bits:

```bash
java -cp target/benchmarks.jar org.openjdk.jmh.Main \
  "benchmark.RsaBenchmarkBC.benchmark(Encrypt|Decrypt)" \
  -f 1 -wi 0 -i 2 -bs 10 -bm ss -p keySize=2048 -foe true
```

## Saída esperada (JMH)

Um bloco de resultado por valor de N. `Cnt` = 15 (rounds), `Score` por chamada, `ss` =
SingleShotTime. Exemplo de um dos runs (cifração/decifração com N=1000):

```
Benchmark                      (keySize)  Mode  Cnt   Score   Error  Units
RsaBenchmark.benchmarkDecrypt       2048    ss   15   1,234 ± 0,045  ms/op
RsaBenchmark.benchmarkDecrypt       4096    ss   15   5,678 ± 0,123  ms/op
RsaBenchmark.benchmarkEncrypt       2048    ss   15   0,456 ± 0,012  ms/op
RsaBenchmark.benchmarkEncrypt       4096    ss   15   1,012 ± 0,030  ms/op
```

Ao final de todos os runs, uma tabela de CPU (medida fora do JMH) é impressa:

```
=== CPU por chamada (medida fora do JMH) ===
Operacao     Chave (bits) Iteracoes  CPU (s)
Geracao      2048         5          0,048...
Cifracao     2048         1000       0,000...
Decifracao   2048         1000       0,001...
```

## Resultados registrados

Os arquivos em `resultados/` documentam as execuções que fundamentam o artigo:

| Arquivo | Conteúdo |
|---|---|
| `resultados_jca_jmh.txt` | Run JMH completo da JCA. A **geração de chaves** permanece válida (não usa OAEP); a seção de cifração/decifração foi substituída pelo arquivo abaixo. |
| `resultados_jca_jmh_encdec_v2.txt` | Cifração/decifração JCA via JMH com `OAEPParameterSpec` (MGF1-SHA256) — **fonte autoritativa** para essas operações. |
| `resultados_jca_vanilla.txt` | Vanilla JCA (código atual, MGF1-SHA256). |
| `resultados_bc_jmh.txt` / `resultados_bc_vanilla.txt` | BouncyCastle (JMH e vanilla). |
