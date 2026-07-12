package benchmark;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;
import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;
import java.security.*;

public class Vanilla {

    static final int[] KEY_SIZES        = {2048, 4096};
    static final int[] GEN_ITERATIONS   = {5, 10, 50, 100};
    static final int[] CRYPTO_ITERATIONS = {10, 100, 1000, 10000};

    // OAEP com SHA-256 tambem no MGF1 (o default da JCA para esta transformacao
    // usa MGF1-SHA1), alinhando a JCA a Python, Go e BouncyCastle
    static final OAEPParameterSpec OAEP_SHA256 = new OAEPParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    record Metrics(double meanS, double stdS, double memPeakKB, double cpuTimeS) {}

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

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws Exception;
    }

    public static void main(String[] args) throws Exception {
        // Gerar chaves uma vez por tamanho (equivalente ao scope="session" do pytest)
        KeyPairGenerator[] generators = new KeyPairGenerator[KEY_SIZES.length];
        KeyPair[]          keyPairs   = new KeyPair[KEY_SIZES.length];
        byte[][]           ciphertexts = new byte[KEY_SIZES.length][];

        // 190 bytes = payload maximo do RSA-2048 com OAEP-SHA256 (k - 2*hLen - 2)
        byte[] plaintext = new byte[190];
        new SecureRandom().nextBytes(plaintext);

        for (int i = 0; i < KEY_SIZES.length; i++) {
            generators[i] = KeyPairGenerator.getInstance("RSA");
            generators[i].initialize(KEY_SIZES[i]);
            keyPairs[i] = generators[i].generateKeyPair();

            Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            enc.init(Cipher.ENCRYPT_MODE, keyPairs[i].getPublic(), OAEP_SHA256);
            ciphertexts[i] = enc.doFinal(plaintext);
        }

        String header = String.format("%-12s %-12s %-10s %-16s %-16s %-14s %-12s",
            "Operacao", "Chave (bits)", "Iteracoes",
            "Media (s)", "Std (s)", "Pico RSS (KB)", "CPU (s)");
        System.out.println(header);
        System.out.println("-".repeat(header.length()));

        // Geração de chave
        for (int ki = 0; ki < KEY_SIZES.length; ki++) {
            final int idx = ki;
            for (int iters : GEN_ITERATIONS) {
                Metrics m = measure(() -> generators[idx].generateKeyPair(), iters);
                printRow("Geracao", KEY_SIZES[ki], iters, m);
            }
        }

        // Cifração — Cipher inicializado uma vez, fora do laco cronometrado (Filosofia A)
        for (int ki = 0; ki < KEY_SIZES.length; ki++) {
            final byte[] pt = plaintext;
            final Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.ENCRYPT_MODE, keyPairs[ki].getPublic(), OAEP_SHA256);
            for (int iters : CRYPTO_ITERATIONS) {
                Metrics m = measure(() -> c.doFinal(pt), iters);
                printRow("Cifracao", KEY_SIZES[ki], iters, m);
            }
        }

        // Decifração — Cipher inicializado uma vez, fora do laco cronometrado (Filosofia A)
        for (int ki = 0; ki < KEY_SIZES.length; ki++) {
            final byte[] ct = ciphertexts[ki];
            final Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.DECRYPT_MODE, keyPairs[ki].getPrivate(), OAEP_SHA256);
            for (int iters : CRYPTO_ITERATIONS) {
                Metrics m = measure(() -> c.doFinal(ct), iters);
                printRow("Decifracao", KEY_SIZES[ki], iters, m);
            }
        }
    }

    static void printRow(String op, int bits, int iters, Metrics m) {
        System.out.printf("%-12s %-12d %-10d %-16.9f %-16.9f %-14.6f %-12.9f%n",
            op, bits, iters, m.meanS(), m.stdS(), m.memPeakKB(), m.cpuTimeS());
    }
}
