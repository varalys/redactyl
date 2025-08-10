package detectors

import "testing"

func TestCloudinaryURLCreds(t *testing.T) {
	data := []byte("cloudinary://1234567890:SeCrEtPassWordToken@mycloud")
	if len(CloudinaryURLCreds("x.txt", data)) == 0 {
		t.Fatalf("expected cloudinary_url_creds finding")
	}
}
