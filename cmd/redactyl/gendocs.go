package redactyl

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/franzer/redactyl/internal/detectors"
	"github.com/spf13/cobra"
)

// gendocs regenerates the detectors categories section in README.md between
// the markers <!-- BEGIN:DETECTORS_CATEGORIES --> and <!-- END:DETECTORS_CATEGORIES -->.
func init() {
	cmd := &cobra.Command{
		Use:   "gendocs",
		Short: "Regenerate README detectors categories",
		RunE: func(_ *cobra.Command, _ []string) error {
			path := "README.md"
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			start := []byte("<!-- BEGIN:DETECTORS_CATEGORIES -->")
			end := []byte("<!-- END:DETECTORS_CATEGORIES -->")
			i := bytes.Index(b, start)
			j := bytes.Index(b, end)
			if i < 0 || j < 0 || j <= i {
				return fmt.Errorf("markers not found in README.md")
			}

			// Simple categorization rules (keep in sync lightly; this is best-effort)
			ids := detectors.IDs()
			var cloud, dburi, cicd, msg, pay, gcloud, aiproviders, aitools, other []string
			for _, id := range ids {
				switch {
				case strings.Contains(id, "aws_") || strings.Contains(id, "gcp_service") || strings.Contains(id, "azure_storage"):
					cloud = append(cloud, id)
				case strings.Contains(id, "_uri_creds"):
					dburi = append(dburi, id)
				case strings.Contains(id, "github_") || strings.Contains(id, "gitlab_") || strings.Contains(id, "npm_") || strings.Contains(id, "terraform_cloud") || strings.Contains(id, "heroku_") || strings.Contains(id, "sentry_") || strings.Contains(id, "docker_config") || strings.Contains(id, "rubygems_") || strings.Contains(id, "npmrc_") || strings.Contains(id, "git_credentials_"):
					cicd = append(cicd, id)
				case strings.Contains(id, "slack_") || strings.Contains(id, "discord_") || strings.Contains(id, "telegram_") || strings.Contains(id, "zapier_") || strings.Contains(id, "ifttt_"):
					msg = append(msg, id)
				case strings.Contains(id, "stripe_") || strings.Contains(id, "sendgrid_") || strings.Contains(id, "mailgun_"):
					pay = append(pay, id)
				case id == "google_api_key" || strings.Contains(id, "firebase_"):
					gcloud = append(gcloud, id)
				case strings.Contains(id, "openai") || strings.Contains(id, "anthropic") || strings.Contains(id, "groq_") || strings.Contains(id, "perplexity") || strings.Contains(id, "replicate") || strings.Contains(id, "openrouter") || strings.Contains(id, "cohere") || strings.Contains(id, "mistral") || strings.Contains(id, "stability") || strings.Contains(id, "ai21") || strings.Contains(id, "azure_openai"):
					aiproviders = append(aiproviders, id)
				case strings.Contains(id, "huggingface") || strings.Contains(id, "wandb") || strings.Contains(id, "kaggle") || strings.Contains(id, "pinecone") || strings.Contains(id, "weaviate") || strings.Contains(id, "qdrant"):
					aitools = append(aitools, id)
				default:
					other = append(other, id)
				}
			}
			var out strings.Builder
			out.WriteString("\nCategories and example IDs (run `redactyl detectors` for the full, up-to-date list):\n\n")
			write := func(title string, ids []string) {
				if len(ids) == 0 {
					return
				}
				sort.Strings(ids)
				out.WriteString("- " + title + ":\n")
				out.WriteString("  - " + strings.Join(ids, ", ") + "\n")
			}
			mergedCloud := append([]string{}, cloud...)
			mergedCloud = append(mergedCloud, dburi...)
			write("Cloud & DB URIs", mergedCloud)
			write("CI/CD & developer services", cicd)
			write("Messaging & webhooks", msg)
			write("Payments & email", pay)
			write("Google & Firebase", gcloud)
			write("AI providers", aiproviders)
			write("AI tooling & vector DBs", aitools)
			write("Other common services", other)

			var nb bytes.Buffer
			nb.Write(b[:i])
			nb.Write(start)
			nb.WriteString("\n")
			nb.WriteString(out.String())
			nb.Write(end)
			nb.Write(b[j+len(end):])
			return os.WriteFile(path, nb.Bytes(), 0644)
		},
	}
	rootCmd.AddCommand(cmd)
}
