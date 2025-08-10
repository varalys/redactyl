package detectors

import "testing"

func TestDatadogKeys(t *testing.T) {
	data := []byte("DD_API_KEY=0123456789abcdef0123456789abcdef\nDD_APP_KEY=0123456789abcdef0123456789abcdef01234567")
	if len(DatadogAPIKey(".env", data)) == 0 {
		t.Fatalf("expected datadog_api_key finding")
	}
	if len(DatadogAppKey(".env", data)) == 0 {
		t.Fatalf("expected datadog_app_key finding")
	}
}
