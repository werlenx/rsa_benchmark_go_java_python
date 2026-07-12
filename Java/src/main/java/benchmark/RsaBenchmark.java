package benchmark;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;
import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;
import java.security.*;
import java.util.concurrent.TimeUnit;


@BenchmarkMode(Mode.SingleShotTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class RsaBenchmark {

    // OAEP com SHA-256 tambem no MGF1 (o default da JCA para esta transformacao
    // usa MGF1-SHA1), alinhando a JCA a Python, Go e BouncyCastle
    static final OAEPParameterSpec OAEP_SHA256 = new OAEPParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    @Param({"2048", "4096"})
    private int keySize;

    private KeyPairGenerator keyGen;
    private PublicKey  publicKey;
    private PrivateKey privateKey;
    private byte[]     ciphertext;
    private byte[]     plaintext;
    // Cipher criado e inicializado uma vez (fora do cronometro): o benchmark
    // isola a operacao criptografica, sem o custo de getInstance/init por chamada.
    private Cipher     encCipher;
    private Cipher     decCipher;


    @Setup(Level.Trial)
    public void setup() throws Exception {
        keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);

        KeyPair pair = keyGen.generateKeyPair();
        publicKey  = pair.getPublic();
        privateKey = pair.getPrivate();

        plaintext = new byte[190];
        new SecureRandom().nextBytes(plaintext);

        encCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        encCipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_SHA256);
        decCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        decCipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_SHA256);

        ciphertext = encCipher.doFinal(plaintext);
    }

    @Benchmark
    public KeyPair benchmarkKeyGen() throws Exception {
        return keyGen.generateKeyPair();
    }

    @Benchmark
    public byte[] benchmarkEncrypt() throws Exception {
        return encCipher.doFinal(plaintext);
    }

    @Benchmark
    public byte[] benchmarkDecrypt() throws Exception {
        return decCipher.doFinal(ciphertext);
    }

    static final int[] KEY_SIZES         = {2048, 4096};
    static final int[] GEN_ITERATIONS    = {5, 10, 50, 100};
    static final int[] CRYPTO_ITERATIONS = {10, 100, 1000, 10000};
    static final int   ROUNDS            = 15;

    public static void main(String[] args) throws Exception {
        // ---- Tempo: JMH, um run por valor de N (batchSize não aceita @Param) ----
        for (int n : GEN_ITERATIONS) {
            new Runner(new OptionsBuilder()
                    .include(RsaBenchmark.class.getSimpleName() + "\\.benchmarkKeyGen")
                    .measurementBatchSize(n)
                    .measurementIterations(ROUNDS)
                    .warmupIterations(0)
                    .build()).run();
        }

        for (int n : CRYPTO_ITERATIONS) {
            new Runner(new OptionsBuilder()
                    .include(RsaBenchmark.class.getSimpleName() + "\\.benchmark(Encrypt|Decrypt)")
                    .measurementBatchSize(n)
                    .measurementIterations(ROUNDS)
                    .warmupIterations(0)
                    .build()).run();
        }

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
        OperatingSystemMXBean os = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();

        byte[] plaintext = new byte[190];
        new SecureRandom().nextBytes(plaintext);

        System.out.println();
        System.out.println("=== CPU por chamada (medida fora do JMH) ===");
        System.out.printf("%-12s %-12s %-10s %-14s%n", "Operacao", "Chave (bits)", "Iteracoes", "CPU (s)");

        for (int bits : KEY_SIZES) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(bits);
            KeyPair pair = kpg.generateKeyPair();
            final PublicKey  pub  = pair.getPublic();
            final PrivateKey priv = pair.getPrivate();

            // Cipher inicializado uma vez, fora do laco cronometrado (Filosofia A)
            final Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            enc.init(Cipher.ENCRYPT_MODE, pub, OAEP_SHA256);
            final byte[] ct = enc.doFinal(plaintext);
            final Cipher dec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            dec.init(Cipher.DECRYPT_MODE, priv, OAEP_SHA256);

            for (int n : GEN_ITERATIONS) {
                printCpu("Geracao", bits, n, measureCpu(os, kpg::generateKeyPair, n));
            }
            for (int n : CRYPTO_ITERATIONS) {
                printCpu("Cifracao", bits, n, measureCpu(os, () -> enc.doFinal(plaintext), n));
            }
            for (int n : CRYPTO_ITERATIONS) {
                printCpu("Decifracao", bits, n, measureCpu(os, () -> dec.doFinal(ct), n));
            }
        }
    }

    static void printCpu(String op, int bits, int n, double cpuS) {
        System.out.printf("%-12s %-12d %-10d %-14.9f%n", op, bits, n, cpuS);
    }
}
