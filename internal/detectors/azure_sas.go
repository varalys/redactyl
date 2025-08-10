package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

// Require both sig and sv parameters (order-insensitive) without lookaheads.
var reAzureSAS = regexp.MustCompile(`https?://[A-Za-z0-9.-]+\.core\.windows\.net/[^?]+\?[^\s]*sig=[^\s&]+[^\s]*sv=[^\s&]+|https?://[A-Za-z0-9.-]+\.core\.windows\.net/[^?]+\?[^\s]*sv=[^\s&]+[^\s]*sig=[^\s&]+`)

func AzureSASToken(path string, data []byte) []types.Finding {
	return findSimple(path, data, reAzureSAS, "azure_sas_token", types.SevHigh, 0.9)
}
