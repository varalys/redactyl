package detectors

import "testing"

func TestShopifyTokens(t *testing.T) {
	data := []byte("shpat_0123456789abcdef0123456789abcdef")
	if len(ShopifyTokens("x.txt", data)) == 0 {
		t.Fatalf("expected shopify_token finding")
	}
}
