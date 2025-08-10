package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reRedisURI = regexp.MustCompile(`\bredis(?:\+ssl)?:/{2}:(?P<pw>[^@\s]+)@`)

func RedisURICreds(path string, data []byte) []types.Finding {
	return findSimple(path, data, reRedisURI, "redis_uri_creds", types.SevHigh, 0.95)
}
