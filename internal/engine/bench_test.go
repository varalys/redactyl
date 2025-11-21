package engine

import (
	"fmt"
	"strings"
	"testing"

	"github.com/redactyl/redactyl/internal/scanner"
	"github.com/redactyl/redactyl/internal/types"
)

type noopScanner struct{}

func (noopScanner) Scan(string, []byte) ([]types.Finding, error) { return nil, nil }

func (noopScanner) ScanWithContext(scanner.ScanContext, []byte) ([]types.Finding, error) {
	return nil, nil
}

func (noopScanner) ScanBatch([]scanner.BatchInput) ([]types.Finding, error) { return nil, nil }

func (noopScanner) Version() (string, error)                            { return "1.0", nil }
func (noopScanner) Detectors() ([]string, error)                          { return nil, nil }

func BenchmarkEngineProcessChunk(b *testing.B) {
	cfg := Config{}
	payload := []byte(strings.Repeat("x", 256))

	chunkSizes := []int{16, 64, 256}
	for _, size := range chunkSizes {
		b.Run(fmt.Sprintf("chunk_%d", size), func(b *testing.B) {
			chunk := make([]pendingScan, size)
			for i := range chunk {
				path := fmt.Sprintf("file-%d.txt", i)
				chunk[i] = pendingScan{
					input:    makeBatchInput(path, payload, nil),
					cacheKey: path,
					cacheVal: fastHash(payload),
				}
			}

			var emitted int
			emit := func(fs []types.Finding) {
				emitted += len(fs)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				updated := map[string]string{}
				res := Result{}
				if err := processChunk(noopScanner{}, cfg, chunk, emit, updated, &res); err != nil {
					b.Fatal(err)
				}
			}
			b.SetBytes(int64(len(payload) * len(chunk)))
		})
	}
}
