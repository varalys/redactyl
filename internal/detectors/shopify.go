package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reShopify = regexp.MustCompile(`\bshp(?:at|ua|ss)_[a-f0-9]{32,}\b`)

func ShopifyTokens(path string, data []byte) []types.Finding {
	return findSimple(path, data, reShopify, "shopify_token", types.SevHigh, 0.95)
}
