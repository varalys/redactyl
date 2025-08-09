package redactyl

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return rootCmd.GenBashCompletion(os.Stdout)
			case "zsh":
				return rootCmd.GenZshCompletion(os.Stdout)
			case "fish":
				return rootCmd.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
		Example: `
# Bash
redactyl completion bash > /etc/bash_completion.d/redactyl

# Zsh
redactyl completion zsh > "${fpath[1]}/_redactyl"

# Fish
redactyl completion fish > ~/.config/fish/completions/redactyl.fish

# PowerShell
redactyl completion powershell > $PROFILE\redactyl.ps1
`,
	}
	rootCmd.AddCommand(cmd)
}
