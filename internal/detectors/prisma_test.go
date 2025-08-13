package detectors

import "testing"

func TestPrismaDataProxyURL(t *testing.T) {
	if len(PrismaDataProxyURL("x.txt", []byte("prisma://project.region/endpoint/path?key=value"))) == 0 {
		t.Fatalf("expected finding")
	}
	if len(PrismaDataProxyURL("x.txt", []byte("notprisma://"))) != 0 {
		t.Fatalf("unexpected")
	}
}
