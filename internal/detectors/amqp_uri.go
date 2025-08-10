package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reAMQPURI = regexp.MustCompile(`\bamqps?://[^:/\s]+:(?P<pw>[^@\s]+)@`)

func AMQPURICreds(path string, data []byte) []types.Finding {
	return findSimple(path, data, reAMQPURI, "amqp_uri_creds", types.SevHigh, 0.95)
}
