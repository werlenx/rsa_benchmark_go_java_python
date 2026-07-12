package benchmark;

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


public class VanillaBC {

    static final int[] KEY_SIZES         = {2048, 4096};
    static final int[] GEN_ITERATIONS    = {5, 10, 50, 100};
    static final int[] CRYPTO_ITERATIONS = {10, 100, 1000, 10000};

    record Metrics(double meanS, double stdS, double memPeakKB, double cpuTimeS) {}

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws Exception;
    }

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

    // Zera o high-water mark de RSS do processo (Linux);
    // instrumento padronizado entre Python, Java e Go
    static void resetPeakRss() {
        try (java.io.FileWriter fw = new java.io.FileWriter("/proc/self/clear_refs")) {
            fw.write("5");
        } catch (java.io.IOException e) {
            // /proc indisponivel: pico refletira o maximo desde o inicio do processo
        }
    }

    // Pico de memoria fisica residente (VmHWM) em KB, medido pelo SO
    static double peakRssKb() {
        try {
            for (String line : java.nio.file.Files.readAllLines(
                    java.nio.file.Paths.get("/proc/self/status"))) {
                if (line.startsWith("VmHWM:")) {
                    return Double.parseDouble(line.replaceAll("\\D+", ""));
                }
            }
        } catch (java.io.IOException e) {
            // ignora
        }
        return 0;
    }

    static Metrics measure(ThrowingRunnable fn, int iterations) throws Exception {
        OperatingSystemMXBean os =
            (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();

        System.gc();
        resetPeakRss();
        long cpuBefore = os.getProcessCpuTime(); // nanoseconds

        double[] times = new double[iterations];
        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            fn.run();
            times[i] = (System.nanoTime() - start) / 1e9;
        }

        long cpuAfter = os.getProcessCpuTime();
        double memPeakKB = peakRssKb();

        double mean = 0;
        for (double t : times) mean += t;
        mean /= iterations;

        double variance = 0;
        for (double t : times) variance += (t - mean) * (t - mean);
        double std = iterations > 1 ? Math.sqrt(variance / (iterations - 1)) : 0;

        // CPU por chamada (user+system), simetrico ao Python (cpu / iterations)
        double cpuTimeS = (cpuAfter - cpuBefore) / 1e9 / iterations;

        return new Metrics(mean, std, memPeakKB, cpuTimeS);
    }

    public static void main(String[] args) throws Exception {
        // Gerar chaves uma vez por tamanho (equivalente ao scope="session" do pytest)
        AsymmetricKeyParameter[] publicKeys  = new AsymmetricKeyParameter[KEY_SIZES.length];
        AsymmetricKeyParameter[] privateKeys = new AsymmetricKeyParameter[KEY_SIZES.length];
        RSAKeyPairGenerator[]    generators  = new RSAKeyPairGenerator[KEY_SIZES.length];
        byte[][]                 ciphertexts = new byte[KEY_SIZES.length][];

        // 190 bytes = payload maximo do RSA-2048 com OAEP-SHA256 (k - 2*hLen - 2)
        byte[] plaintext = new byte[190];
        new SecureRandom().nextBytes(plaintext);

        for (int i = 0; i < KEY_SIZES.length; i++) {
            generators[i] = newKeyGen(KEY_SIZES[i]);
            AsymmetricCipherKeyPair pair = generators[i].generateKeyPair();
            publicKeys[i]  = pair.getPublic();
            privateKeys[i] = pair.getPrivate();
            ciphertexts[i] = encrypt(publicKeys[i], plaintext);

            if (!Arrays.equals(decrypt(privateKeys[i], ciphertexts[i]), plaintext)) {
                throw new IllegalStateException("BouncyCastle: round-trip OAEP falhou");
            }
        }

        String header = String.format("%-12s %-12s %-10s %-16s %-16s %-14s %-12s",
            "Operacao", "Chave (bits)", "Iteracoes",
            "Media (s)", "Std (s)", "Pico RSS (KB)", "CPU (s)");
        System.out.println(header);
        System.out.println("-".repeat(header.length()));

        // Geração de chave
        for (int ki = 0; ki < KEY_SIZES.length; ki++) {
            final RSAKeyPairGenerator gen = generators[ki];
            for (int iters : GEN_ITERATIONS) {
                Metrics m = measure(gen::generateKeyPair, iters);
                printRow("Geracao", KEY_SIZES[ki], iters, m);
            }
        }

        // Cifração — engine OAEP inicializado uma vez, fora do laco (Filosofia A)
        for (int ki = 0; ki < KEY_SIZES.length; ki++) {
            final byte[] pt = plaintext;
            final AsymmetricBlockCipher enc = newOaep();
            enc.init(true, publicKeys[ki]);
            for (int iters : CRYPTO_ITERATIONS) {
                Metrics m = measure(() -> enc.processBlock(pt, 0, pt.length), iters);
                printRow("Cifracao", KEY_SIZES[ki], iters, m);
            }
        }

        // Decifração — engine OAEP inicializado uma vez, fora do laco (Filosofia A)
        for (int ki = 0; ki < KEY_SIZES.length; ki++) {
            final byte[] ct = ciphertexts[ki];
            final AsymmetricBlockCipher dec = newOaep();
            dec.init(false, privateKeys[ki]);
            for (int iters : CRYPTO_ITERATIONS) {
                Metrics m = measure(() -> dec.processBlock(ct, 0, ct.length), iters);
                printRow("Decifracao", KEY_SIZES[ki], iters, m);
            }
        }
    }

    static void printRow(String op, int bits, int iters, Metrics m) {
        System.out.printf("%-12s %-12d %-10d %-16.9f %-16.9f %-14.6f %-12.9f%n",
            op, bits, iters, m.meanS(), m.stdS(), m.memPeakKB(), m.cpuTimeS());
    }
}
