package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var (
	reWandbCtx   = regexp.MustCompile(`(?i)WANDB_API_KEY|weights\s*&\s*biases|wandb`)
	reWandbToken = regexp.MustCompile(`\b[A-Za-z0-9]{32,64}\b`)
)

func WeightsBiasesAPIKey(path string, data []byte) []types.Finding {
	return findWithContext(path, data, reWandbCtx, reWandbToken, "wandb_api_key", types.SevHigh, 0.9)
}
