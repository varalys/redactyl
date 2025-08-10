package detectors

import "testing"

func TestTelegramBotToken(t *testing.T) {
	data := []byte("1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi-jklmn")
	if len(TelegramBotToken("x.txt", data)) == 0 {
		t.Fatalf("expected telegram_bot_token finding")
	}
}
