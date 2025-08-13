package detectors

import "testing"

func TestNetlifyBuildHookURL(t *testing.T) {
	if len(NetlifyBuildHookURL("x.txt", []byte("https://api.netlify.com/build_hooks/AbCdEfGhIjKlMnOpQrSt"))) == 0 {
		t.Fatalf("expected finding")
	}
	if len(NetlifyBuildHookURL("x.txt", []byte("https://api.netlify.com/build_hooks/short"))) != 0 {
		t.Fatalf("unexpected")
	}
}
