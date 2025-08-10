package detectors

import "testing"

func TestWandbAPIKey(t *testing.T) {
	data := []byte("WANDB_API_KEY=abcdefghijklmnopqrstuvwxyzABCDEFGH1234")
	fs := WeightsBiasesAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected wandb_api_key finding")
	}
}
