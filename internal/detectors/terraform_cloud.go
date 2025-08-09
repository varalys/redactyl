package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reTerraformCloud = regexp.MustCompile(`\btf[ec]\.[A-Za-z0-9]{30,}\b`)

func TerraformCloudToken(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if m := reTerraformCloud.FindString(sc.Text()); m != "" {
			out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "terraform_cloud_token", Severity: types.SevHigh, Confidence: 0.9})
		}
	}
	return out
}
