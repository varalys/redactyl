package detectors

import "testing"

func TestRedisURICreds(t *testing.T) {
	data := []byte("redis://:supersecret@host:6379")
	if len(RedisURICreds("x.txt", data)) == 0 {
		t.Fatalf("expected redis_uri_creds finding")
	}
}
