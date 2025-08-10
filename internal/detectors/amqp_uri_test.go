package detectors

import "testing"

func TestAMQPURICreds(t *testing.T) {
	data := []byte("amqps://user:secret@broker/vhost")
	if len(AMQPURICreds("x.txt", data)) == 0 {
		t.Fatalf("expected amqp_uri_creds finding")
	}
}
