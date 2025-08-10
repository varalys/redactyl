package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reDiscordBotToken = regexp.MustCompile(`^[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}$`)

func DiscordBotToken(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		t := sc.Text()
		if m := reDiscordBotToken.FindString(t); m != "" {
			out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "discord_bot_token", Severity: types.SevHigh, Confidence: 0.95})
		}
	}
	return out
}
