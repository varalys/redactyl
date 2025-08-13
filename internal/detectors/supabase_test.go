package detectors

import "testing"

func TestSupabaseServiceRoleKey(t *testing.T) {
	pos := "SUPABASE_SERVICE_ROLE_KEY='service-role-secret-123456'"
	if len(SupabaseServiceRoleKey("x.txt", []byte(pos))) == 0 {
		t.Fatalf("expected finding")
	}
	neg := "SUPABASE_SERVICE_ROLE_KEY = \"\""
	if len(SupabaseServiceRoleKey("x.txt", []byte(neg))) != 0 {
		t.Fatalf("unexpected")
	}
}
