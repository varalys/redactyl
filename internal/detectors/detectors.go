package detectors

import "github.com/franzer/redactyl/internal/types"

type Detector func(path string, data []byte) []types.Finding

var all = []Detector{
	AWSKeys, GitHubToken, SlackToken, JWTToken, PrivateKeyBlock, EntropyNearbySecrets, StripeSecret, Twilio,
	GoogleAPIKey, GitLabToken, SendGridAPIKey, SlackWebhookURL, DiscordWebhookURL, OpenAIAPIKey, NPMToken, StripeWebhookSecret, GCPServiceAccountKey,
	MailgunAPIKey, DBURIs, AzureStorageKey, TerraformCloudToken, HerokuAPIKey, SentryDSN, FirebaseAPIKey,
	// New AI providers
	AnthropicAPIKey, GroqAPIKey, PerplexityAPIKey, ReplicateAPIToken, OpenRouterAPIKey,
	CohereAPIKey, MistralAPIKey, StabilityAPIKey, AI21APIKey, AzureOpenAIAPIKey,
	// AI tooling & vector DBs
	HuggingFaceToken, WeightsBiasesAPIKey, KaggleJSONKey, PineconeAPIKey, WeaviateAPIKey, QdrantAPIKey,
	// More services & bot tokens
	CloudflareTokens, DatadogAPIKey, DatadogAppKey, MapboxToken, TelegramBotToken, SnykToken, DatabricksPAT, ShopifyTokens, NotionAPIKey, PyPIToken, AzureSASToken, CloudinaryURLCreds, RedisURICreds, AMQPURICreds, SQLServerURICreds,
	DiscordBotToken,
	// File-format leaks
	NPMRCAuthToken, RubyGemsCredentials, DockerConfigAuth, GitCredentialsURLSecret,
}

func RunAll(path string, data []byte) []types.Finding {
	var out []types.Finding
	for _, d := range all {
		out = append(out, d(path, data)...)
	}
	return dedupe(out)
}

func IDs() []string {
	return []string{
		"aws_access_key",
		"aws_secret_key",
		"github_token",
		"slack_token",
		"jwt",
		"private_key_block",
		"entropy_context",
		"stripe_secret",
		"stripe_webhook_secret",
		"twilio_account_sid",
		"twilio_api_key_sid",
		"twilio_auth_token",
		"twilio_api_key_secret_like",
		"google_api_key",
		"gitlab_token",
		"sendgrid_api_key",
		"slack_webhook",
		"discord_webhook",
		"openai_api_key",
		"npm_token",
		"gcp_service_account_key",
		"mailgun_api_key",
		"postgres_uri_creds",
		"mysql_uri_creds",
		"mongodb_uri_creds",
		"azure_storage_key",
		"terraform_cloud_token",
		"heroku_api_key",
		"sentry_dsn",
		"firebase_api_key",
		// New IDs
		"anthropic_api_key",
		"groq_api_key",
		"perplexity_api_key",
		"replicate_api_token",
		"openrouter_api_key",
		"cohere_api_key",
		"mistral_api_key",
		"stability_api_key",
		"ai21_api_key",
		"azure_openai_api_key",
		"huggingface_token",
		"wandb_api_key",
		"kaggle_json_key",
		"pinecone_api_key",
		"weaviate_api_key",
		"qdrant_api_key",
		"cloudflare_token",
		"datadog_api_key",
		"datadog_app_key",
		"mapbox_token",
		"telegram_bot_token",
		"snyk_token",
		"databricks_pat",
		"shopify_token",
		"notion_api_key",
		"pypi_token",
		"azure_sas_token",
		"cloudinary_url_creds",
		"redis_uri_creds",
		"amqp_uri_creds",
		"sqlserver_uri_creds",
		"discord_bot_token",
		"npmrc_auth_token",
		"rubygems_credentials",
		"docker_config_auth",
		"git_credentials_url_secret",
	}
}

// Simple function IDs for detector testing (coarse-grained groups)
var funcByID = map[string]Detector{
	"aws":        AWSKeys,
	"github":     GitHubToken,
	"slack":      SlackToken,
	"jwt":        JWTToken,
	"privatekey": PrivateKeyBlock,
	"entropy":    EntropyNearbySecrets,
	"stripe":     StripeSecret,
	"twilio":     Twilio,
	"google":     GoogleAPIKey,
	"gitlab":     GitLabToken,
	"sendgrid":   SendGridAPIKey,
	"slackweb":   SlackWebhookURL,
	"discord":    DiscordWebhookURL,
	"openai":     OpenAIAPIKey,
	"npm":        NPMToken,
	"gcp":        GCPServiceAccountKey,
	"mailgun":    MailgunAPIKey,
	"dburi":      DBURIs,
	"azure":      AzureStorageKey,
	"tfc":        TerraformCloudToken,
	"heroku":     HerokuAPIKey,
	"sentry":     SentryDSN,
	"firebase":   FirebaseAPIKey,
	// New groups
	"anthropic":  AnthropicAPIKey,
	"groq":       GroqAPIKey,
	"pplx":       PerplexityAPIKey,
	"replicate":  ReplicateAPIToken,
	"openrouter": OpenRouterAPIKey,
	"cohere":     CohereAPIKey,
	"mistral":    MistralAPIKey,
	"stability":  StabilityAPIKey,
	"ai21":       AI21APIKey,
	"azopenai":   AzureOpenAIAPIKey,
	"hf":         HuggingFaceToken,
	"wandb":      WeightsBiasesAPIKey,
	"kaggle":     KaggleJSONKey,
	"pinecone":   PineconeAPIKey,
	"weaviate":   WeaviateAPIKey,
	"qdrant":     QdrantAPIKey,
	"cloudflare": CloudflareTokens,
	"datadog":    DatadogAPIKey,
	"mapbox":     MapboxToken,
	"telegram":   TelegramBotToken,
	"snyk":       SnykToken,
	"databricks": DatabricksPAT,
	"shopify":    ShopifyTokens,
	"notion":     NotionAPIKey,
	"pypi":       PyPIToken,
	"azsas":      AzureSASToken,
	"cloudinary": CloudinaryURLCreds,
	"redis":      RedisURICreds,
	"amqp":       AMQPURICreds,
	"mssql":      SQLServerURICreds,
	"discbot":    DiscordBotToken,
	"npmrc":      NPMRCAuthToken,
	"rubygems":   RubyGemsCredentials,
	"docker":     DockerConfigAuth,
	"gitcreds":   GitCredentialsURLSecret,
}

func FunctionIDs() []string {
	return []string{"aws", "github", "slack", "jwt", "privatekey", "entropy", "stripe", "twilio", "google", "gitlab", "sendgrid", "slackweb", "discord", "openai", "npm", "gcp", "mailgun", "dburi", "azure", "tfc", "heroku", "sentry", "firebase", "anthropic", "groq", "pplx", "replicate", "openrouter", "cohere", "mistral", "stability", "ai21", "azopenai", "hf", "wandb", "kaggle", "pinecone", "weaviate", "qdrant", "cloudflare", "datadog", "mapbox", "telegram", "snyk", "databricks", "shopify", "notion", "pypi", "azsas", "cloudinary", "redis", "amqp", "mssql", "discbot", "npmrc", "rubygems", "docker", "gitcreds"}
}

func RunFunction(id, path string, data []byte) []types.Finding {
	if f, ok := funcByID[id]; ok {
		return f(path, data)
	}
	return nil
}

func dedupe(findings []types.Finding) []types.Finding {
	seen := make(map[string]bool)
	var result []types.Finding

	for _, f := range findings {
		key := f.Path + "|" + f.Detector + "|" + f.Match
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}
	return result
}
