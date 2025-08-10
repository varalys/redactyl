package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reAzOAIContext = regexp.MustCompile(`(?i)azure_openai|AZURE_OPENAI_API_KEY|api-key`)

func AzureOpenAIAPIKey(path string, data []byte) []types.Finding {
	return findWithContext(path, data, reAzOAIContext, reGenericKey32to64, "azure_openai_api_key", types.SevHigh, 0.9)
}
