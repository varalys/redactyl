package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reTelegram = regexp.MustCompile(`\b\d{9,10}:[A-Za-z0-9_-]{35,}\b`)

func TelegramBotToken(path string, data []byte) []types.Finding {
	return findSimple(path, data, reTelegram, "telegram_bot_token", types.SevHigh, 0.95)
}
