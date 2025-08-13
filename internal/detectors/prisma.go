package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var rePrismaDataProxyURL = regexp.MustCompile(`\bprisma://[A-Za-z0-9._-]+/[^ \t\r\n'"<>]+`)

func PrismaDataProxyURL(path string, data []byte) []types.Finding {
	return findSimple(path, data, rePrismaDataProxyURL, "prisma_data_proxy_url", types.SevHigh, 0.95)
}
