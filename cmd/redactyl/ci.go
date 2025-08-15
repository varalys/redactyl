package redactyl

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func init() {
	ci := &cobra.Command{Use: "ci", Short: "CI template helpers for multiple providers"}
	rootCmd.AddCommand(ci)

	var provider string
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write a CI pipeline template for your provider",
		RunE: func(_ *cobra.Command, _ []string) error {
			var path string
			var content string
			switch provider {
			case "gitlab":
				path = ".gitlab-ci.yml"
				content = `stages: [scan]
scan:
  stage: scan
  image: golang:1.22
  script:
    - go version
    - go build -o bin/redactyl .
    - ./bin/redactyl scan --json --fail-on medium | tee redactyl-findings.json
  artifacts:
    when: always
    paths:
      - redactyl-findings.json
`
			case "bitbucket":
				path = "bitbucket-pipelines.yml"
				content = `pipelines:
  default:
    - step:
        name: Redactyl Scan
        image: golang:1.22
        caches:
          - go
        script:
          - go version
          - go build -o bin/redactyl .
          - ./bin/redactyl scan --json --fail-on medium | tee redactyl-findings.json
        artifacts:
          - redactyl-findings.json
`
			case "azure":
				path = "azure-pipelines.yml"
				content = `trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: GoTool@0
  inputs:
    version: '1.22.x'
- script: |
    go version
    go build -o bin/redactyl .
    ./bin/redactyl scan --json --fail-on medium | tee redactyl-findings.json
  displayName: 'Redactyl Scan'
- publish: redactyl-findings.json
  artifact: redactyl-findings
  condition: succeededOrFailed()
`
			default:
				return fmt.Errorf("unknown --provider. Supported: gitlab, bitbucket, azure")
			}
			// ensure parent directories exist if needed
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				return err
			}
			fmt.Println("Wrote", path)
			return nil
		},
	}
	initCmd.Flags().StringVar(&provider, "provider", "", "CI provider: gitlab | bitbucket | azure")
	if err := initCmd.MarkFlagRequired("provider"); err != nil {
		// fallback: print a hint if cobra API changes
		fmt.Fprintln(os.Stderr, "warning: could not mark --provider as required:", err)
	}
	ci.AddCommand(initCmd)
}
