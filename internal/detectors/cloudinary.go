package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reCloudinary = regexp.MustCompile(`\bcloudinary://\d{6,}:[A-Za-z0-9_-]{10,}@`)

func CloudinaryURLCreds(path string, data []byte) []types.Finding {
	return findSimple(path, data, reCloudinary, "cloudinary_url_creds", types.SevHigh, 0.95)
}
