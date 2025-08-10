package detectors

import "testing"

func TestNPMRCAuthToken(t *testing.T) {
	data := []byte("//registry.npmjs.org/:_authToken=abcdEFGHijklMNOPqrstUVWXyz0123456789")
	if len(NPMRCAuthToken(".npmrc", data)) == 0 {
		t.Fatalf("expected npmrc_auth_token finding")
	}
}

func TestRubyGemsCredentials(t *testing.T) {
	data := []byte(":rubygems_api_key: 1234567890abcdef1234567890abcdef")
	if len(RubyGemsCredentials(".gem/credentials", data)) == 0 {
		t.Fatalf("expected rubygems_credentials finding")
	}
}

func TestDockerConfigAuth(t *testing.T) {
	data := []byte(`{"auths": {"registry.example": {"auth": "dXNlcjpzZWNyZXQ="}}}`)
	if len(DockerConfigAuth("config.json", data)) == 0 {
		t.Fatalf("expected docker_config_auth finding")
	}
}

func TestGitCredentialsURLSecret(t *testing.T) {
	data := []byte("https://user:password@git.example.com/repo.git")
	if len(GitCredentialsURLSecret(".git-credentials", data)) == 0 {
		t.Fatalf("expected git_credentials_url_secret finding")
	}
}
