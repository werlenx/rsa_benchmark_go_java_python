package benchmark;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;

import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;


@BenchmarkMode(Mode.SingleShotTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class RsaBenchmarkBC {

    @Param({"2048", "4096"})
    private int keySize;

    private RSAKeyPairGenerator    keyGen;
    private AsymmetricKeyParameter publicKey;
    private AsymmetricKeyParameter privateKey;
    private byte[]                 ciphertext;
    private byte[]                 plaintext;
    // Engines OAEP criados e inicializados uma vez (fora do cronometro): o
    // benchmark isola a operacao criptografica, sem newOaep()/init por chamada.
    private AsymmetricBlockCipher  encEngine;
    private AsymmetricBlockCipher  decEngine;

    static AsymmetricBlockCipher newOaep() {
        return new OAEPEncoding(new RSAEngine(), new SHA256Digest(), new SHA256Digest(), null);
    }

    static RSAKeyPairGenerator newKeyGen(int bits) {
        RSAKeyPairGenerator g = new RSAKeyPairGenerator();
        g.init(new RSAKeyGenerationParameters(
            BigInteger.valueOf(65537), new SecureRandom(), bits, 100));
        return g;
    }

    static byte[] encrypt(AsymmetricKeyParameter pub, byte[] msg) throws Exception {
        AsymmetricBlockCipher c = newOaep();
        c.init(true, pub);
        return c.processBlock(msg, 0, msg.length);
    }

    static byte[] decrypt(AsymmetricKeyParameter priv, byte[] ct) throws Exception {
        AsymmetricBlockCipher c = newOaep();
        c.init(false, priv);
        return c.processBlock(ct, 0, ct.length);
    }

    // Equivalente ao scope="session": chaves geradas uma vez por parametrização.
    @Setup(Level.Trial)
    public void setup() throws Exception {
        keyGen = newKeyGen(keySize);
        AsymmetricCipherKeyPair pair = keyGen.generateKeyPair();
        publicKey  = pair.getPublic();
        privateKey = pair.getPrivate();

        plaintext = new byte[190];
        new SecureRandom().nextBytes(plaintext);
        ciphertext = encrypt(publicKey, plaintext);

        // Sanidade: garante que o caminho BC está correto (não "rápido por estar quebrado").
        if (!Arrays.equals(decrypt(privateKey, ciphertext), plaintext)) {
            throw new IllegalStateException("BouncyCastle: round-trip OAEP falhou");
        }

        encEngine = newOaep();
        encEngine.init(true, publicKey);
        decEngine = newOaep();
        decEngine.init(false, privateKey);
    }

    @Benchmark
    public AsymmetricCipherKeyPair benchmarkKeyGen() {
        return keyGen.generateKeyPair();
    }

    @Benchmark
    public byte[] benchmarkEncrypt() throws Exception {
        return encEngine.processBlock(plaintext, 0, plaintext.length);
    }

    @Benchmark
    public byte[] benchmarkDecrypt() throws Exception {
        return decEngine.processBlock(ciphertext, 0, ciphertext.length);
    }

    static final int[] KEY_SIZES         = {2048, 4096};
    static final int[] GEN_ITERATIONS    = {5, 10, 50, 100};
    static final int[] CRYPTO_ITERATIONS = {10, 100, 1000, 10000};
    static final int   ROUNDS            = 15;

    public static void main(String[] args) throws Exception {
        // ---- Tempo: JMH, um run por valor de N (batchSize não aceita @Param) ----
        for (int n : GEN_ITERATIONS) {
            new Runner(new OptionsBuilder()
                    .include(RsaBenchmarkBC.class.getSimpleName() + "\\.benchmarkKeyGen")
                    .measurementBatchSize(n)
                    .measurementIterations(ROUNDS)
                    .warmupIterations(0)
                    .build()).run();
        }

        for (int n : CRYPTO_ITERATIONS) {
            new Runner(new OptionsBuilder()
                    .include(RsaBenchmarkBC.class.getSimpleName() + "\\.benchmark(Encrypt|Decrypt)")
                    .measurementBatchSize(n)
                    .measurementIterations(ROUNDS)
                    .warmupIterations(0)
                    .build()).run();
        }

        // ---- CPU: medida fora do JMH (paralelo à fixture `measure` do Python) ----
        measureCpuPass();
    }

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws Exception;
    }

    static double measureCpu(OperatingSystemMXBean os, ThrowingRunnable fn, int n) throws Exception {
        long before = os.getProcessCpuTime();   // nanosegundos
        for (int i = 0; i < n; i++) {
            fn.run();
        }
        long after = os.getProcessCpuTime();
        return (after - before) / 1e9 / n;       // segundos por chamada
    }

    static void measureCpuPass() throws Exception {
        OperatingSystemMXBean os =
            (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();

        byte[] plaintext = new byte[190];
        new SecureRandom().nextBytes(plaintext);

        System.out.println();
        System.out.println("=== CPU por chamada (BouncyCastle, medida fora do JMH) ===");
        System.out.printf("%-12s %-12s %-10s %-14s%n",
            "Operacao", "Chave (bits)", "Iteracoes", "CPU (s)");

        for (int bits : KEY_SIZES) {
            final RSAKeyPairGenerator kpg = newKeyGen(bits);
            AsymmetricCipherKeyPair pair = kpg.generateKeyPair();
            final AsymmetricKeyParameter pub  = pair.getPublic();
            final AsymmetricKeyParameter priv = pair.getPrivate();
            final byte[] ct = encrypt(pub, plaintext);

            // Engines inicializados uma vez, fora do laco cronometrado (Filosofia A)
            final AsymmetricBlockCipher enc = newOaep();
            enc.init(true, pub);
            final AsymmetricBlockCipher dec = newOaep();
            dec.init(false, priv);

            for (int n : GEN_ITERATIONS) {
                printCpu("Geracao", bits, n, measureCpu(os, kpg::generateKeyPair, n));
            }
            for (int n : CRYPTO_ITERATIONS) {
                printCpu("Cifracao", bits, n,
                    measureCpu(os, () -> enc.processBlock(plaintext, 0, plaintext.length), n));
            }
            for (int n : CRYPTO_ITERATIONS) {
                printCpu("Decifracao", bits, n,
                    measureCpu(os, () -> dec.processBlock(ct, 0, ct.length), n));
            }
        }
    }

    static void printCpu(String op, int bits, int n, double cpuS) {
        System.out.printf("%-12s %-12d %-10d %-14.9f%n", op, bits, n, cpuS);
    }
}
