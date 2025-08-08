package redactyl

import (
	"runtime/debug"

	semver3 "github.com/blang/semver"
	semver "github.com/blang/semver/v4"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

func selfUpdate() error {
	v := version
	// Use build info if tag overridden at build-time
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(v) == 0 {
				v = s.Value
			}
		}
	}
	// parse semantic version (strip leading v)
	ver, err := semver.ParseTolerant(v)
	if err != nil {
		ver = semver.MustParse("0.0.0")
	}
	// Update from GitHub Releases: redactyl/redactyl
	latest, err := selfupdate.UpdateSelf(semver3.MustParse(ver.String()), "redactyl/redactyl")
	if err != nil {
		return err
	}
	_ = latest
	return nil
}

func pickString(cli string, local, global *string) string {
	if cli != "" {
		return cli
	}
	if local != nil && *local != "" {
		return *local
	}
	if global != nil && *global != "" {
		return *global
	}
	return ""
}

func pickInt(cli int, local, global *int) int {
	if cli != 0 {
		return cli
	}
	if local != nil && *local != 0 {
		return *local
	}
	if global != nil && *global != 0 {
		return *global
	}
	return 0
}

func pickInt64(cli int64, local, global *int64) int64 {
	if cli != 0 {
		return cli
	}
	if local != nil && *local != 0 {
		return *local
	}
	if global != nil && *global != 0 {
		return *global
	}
	return 0
}

func pickFloat(cli float64, local, global *float64) float64 {
	if cli != 0 {
		return cli
	}
	if local != nil && *local != 0 {
		return *local
	}
	if global != nil && *global != 0 {
		return *global
	}
	return 0
}

func pickBool(cli bool, local, global *bool) bool {
	if cli {
		return true
	}
	if local != nil {
		return *local
	}
	if global != nil {
		return *global
	}
	return false
}
