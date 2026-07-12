package rsabenchmark

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
	"testing"
	"time"
)

var (
	privateKey2048 *rsa.PrivateKey
	privateKey4096 *rsa.PrivateKey
	ciphertext2048 []byte
	ciphertext4096 []byte
)

var (
	keySizes         = []int{2048, 4096}
	genIterations    = []int{5, 10, 50, 100}
	cryptoIterations = []int{10, 100, 1000, 10000}
)

const rounds = 15

func init() {
	var err error
	privateKey2048, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	privateKey4096, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 190) // payload maximo do RSA-2048 OAEP-SHA256
	rand.Read(msg)

	ciphertext2048, _ = rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey2048.PublicKey, msg, nil)
	ciphertext4096, _ = rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey4096.PublicKey, msg, nil)
}

func keyFor(bits int) *rsa.PrivateKey {
	if bits == 2048 {
		return privateKey2048
	}
	return privateKey4096
}

func ciphertextFor(bits int) []byte {
	if bits == 2048 {
		return ciphertext2048
	}
	return ciphertext4096
}

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

func runPedantic(b *testing.B, n int, fn func()) {
	totalCalls := float64(rounds * n)

	runtime.GC()
	resetPeakRSS()
	cpuBefore := cpuSeconds()

	times := make([]float64, rounds)
	for r := 0; r < rounds; r++ {
		start := time.Now()
		for i := 0; i < n; i++ {
			fn()
		}
		times[r] = time.Since(start).Seconds() / float64(n)
	}

	cpuAfter := cpuSeconds()
	// Pico RSS do lote inteiro (pico não é normalizável por chamada)
	memKB := peakRSSKB()

	mean, std := meanStd(times)
	cpuS := (cpuAfter - cpuBefore) / totalCalls

	b.ReportMetric(mean, "s/op")
	b.ReportMetric(std, "std-s")
	b.ReportMetric(memKB, "peak-rss-KB")
	b.ReportMetric(cpuS, "cpu-s")
	b.ReportMetric(0, "ns/op")
}

func meanStd(xs []float64) (mean, std float64) {
	for _, x := range xs {
		mean += x
	}
	mean /= float64(len(xs))

	if len(xs) > 1 {
		var variance float64
		for _, x := range xs {
			variance += (x - mean) * (x - mean)
		}
		std = math.Sqrt(variance / float64(len(xs)-1))
	}
	return mean, std
}

func BenchmarkKeyGen(b *testing.B) {
	for _, bits := range keySizes {
		for _, n := range genIterations {
			b.Run(fmt.Sprintf("bits=%d/iters=%d", bits, n), func(b *testing.B) {
				runPedantic(b, n, func() {
					if _, err := rsa.GenerateKey(rand.Reader, bits); err != nil {
						b.Fatal(err)
					}
				})
			})
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	msg := make([]byte, 190) // payload maximo do RSA-2048 OAEP-SHA256
	rand.Read(msg)
	for _, bits := range keySizes {
		key := keyFor(bits)
		for _, n := range cryptoIterations {
			b.Run(fmt.Sprintf("bits=%d/iters=%d", bits, n), func(b *testing.B) {
				runPedantic(b, n, func() {
					if _, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, msg, nil); err != nil {
						b.Fatal(err)
					}
				})
			})
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for _, bits := range keySizes {
		key := keyFor(bits)
		ct := ciphertextFor(bits)
		for _, n := range cryptoIterations {
			b.Run(fmt.Sprintf("bits=%d/iters=%d", bits, n), func(b *testing.B) {
				runPedantic(b, n, func() {
					if _, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ct, nil); err != nil {
						b.Fatal(err)
					}
				})
			})
		}
	}
}
