//go:build ignore

// Standalone: execute com `go run vanilla.go`. A tag ignore evita conflito de
// pacote (main vs rsabenchmark) com benchmark_test.go ao rodar `go test`.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Parâmetros equivalentes ao benchmark Python
var (
	keySizes         = []int{2048, 4096}
	genIterations    = []int{5, 10, 50, 100}
	cryptoIterations = []int{10, 100, 1000, 10000}
)

type metrics struct {
	meanS     float64
	stdS      float64
	memPeakKB float64
	cpuTimeS  float64
}

// resetPeakRSS zera o high-water mark de RSS do processo (Linux);
// instrumento padronizado entre Python, Java e Go.
func resetPeakRSS() {
	_ = os.WriteFile("/proc/self/clear_refs", []byte("5"), 0)
}

// peakRSSKB retorna o pico de memória física residente (VmHWM) em KB,
// medido pelo SO.
func peakRSSKB() float64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmHWM:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseFloat(fields[1], 64)
				return v
			}
		}
	}
	return 0
}

// cpuSeconds retorna o tempo de CPU do processo (user + system) em segundos,
// via getrusage — mesma fonte usada no benchmark com framework.
func cpuSeconds() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	toS := func(tv syscall.Timeval) float64 {
		return float64(tv.Sec) + float64(tv.Usec)/1e6
	}
	return toS(ru.Utime) + toS(ru.Stime)
}

func measure(fn func(), iterations int) metrics {
	runtime.GC()
	resetPeakRSS()
	cpuBefore := cpuSeconds()

	times := make([]float64, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		fn()
		times[i] = time.Since(start).Seconds()
	}

	cpuAfter := cpuSeconds()
	peakKB := peakRSSKB()

	mean := 0.0
	for _, t := range times {
		mean += t
	}
	mean /= float64(iterations)

	variance := 0.0
	for _, t := range times {
		variance += (t - mean) * (t - mean)
	}
	std := 0.0
	if iterations > 1 {
		std = math.Sqrt(variance / float64(iterations-1))
	}

	// CPU por chamada (user+system), simétrico ao Python (cpu / iterations)
	cpuTimeS := (cpuAfter - cpuBefore) / float64(iterations)

	return metrics{
		meanS:     mean,
		stdS:      std,
		memPeakKB: peakKB,
		cpuTimeS:  cpuTimeS,
	}
}

func main() {
	// Gerar chaves uma vez por tamanho (equivalente ao scope="session" do pytest)
	keys := make(map[int]*rsa.PrivateKey)
	for _, bits := range keySizes {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			panic(err)
		}
		keys[bits] = key
	}

	type row struct {
		op    string
		bits  int
		iters int
		m     metrics
	}
	var results []row

	// Geração de chave
	for _, bits := range keySizes {
		for _, iters := range genIterations {
			b := bits
			m := measure(func() {
				_, err := rsa.GenerateKey(rand.Reader, b)
				if err != nil {
					panic(err)
				}
			}, iters)
			results = append(results, row{"Geracao", bits, iters, m})
		}
	}

	// Cifração
	// 190 bytes = payload maximo do RSA-2048 com OAEP-SHA256 (k - 2*hLen - 2)
	msg := make([]byte, 190)
	rand.Read(msg)
	for _, bits := range keySizes {
		key := keys[bits]
		for _, iters := range cryptoIterations {
			m := measure(func() {
				_, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, msg, nil)
				if err != nil {
					panic(err)
				}
			}, iters)
			results = append(results, row{"Cifracao", bits, iters, m})
		}
	}

	// Decifração
	ciphertexts := make(map[int][]byte)
	for _, bits := range keySizes {
		ct, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &keys[bits].PublicKey, msg, nil)
		ciphertexts[bits] = ct
	}
	for _, bits := range keySizes {
		key := keys[bits]
		ct := ciphertexts[bits]
		for _, iters := range cryptoIterations {
			m := measure(func() {
				_, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ct, nil)
				if err != nil {
					panic(err)
				}
			}, iters)
			results = append(results, row{"Decifracao", bits, iters, m})
		}
	}

	// Imprimir tabela
	header := fmt.Sprintf("%-12s %-12s %-10s %-14s %-14s %-14s %-12s",
		"Operacao", "Chave (bits)", "Iteracoes", "Media (s)", "Std (s)", "Pico RSS (KB)", "CPU (s)")
	sep := fmt.Sprintf("%s", "")
	for i := 0; i < len(header); i++ {
		sep += "-"
	}
	fmt.Println(header)
	fmt.Println(sep)
	for _, r := range results {
		fmt.Printf("%-12s %-12d %-10d %-14.9f %-14.9f %-14.6f %-12.9f\n",
			r.op, r.bits, r.iters,
			r.m.meanS, r.m.stdS, r.m.memPeakKB, r.m.cpuTimeS)
	}
}
