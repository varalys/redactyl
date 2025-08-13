package detectors

import "testing"

func TestHasuraAdminSecret(t *testing.T) {
	pos := "HASURA_GRAPHQL_ADMIN_SECRET=SuperSecretValue12345"
	if len(HasuraAdminSecret("x.txt", []byte(pos))) == 0 {
		t.Fatalf("expected finding")
	}
	neg := "HASURA_GRAPHQL_ADMIN_SECRET = ''"
	if len(HasuraAdminSecret("x.txt", []byte(neg))) != 0 {
		t.Fatalf("unexpected")
	}
}
