# Release Process

1. Ensure `main` is green (tests, lint, vuln check).
2. Update changelog in GitHub Releases body.
3. Tag the release locally or in GitHub: `vX.Y.Z`.
4. CI will run GoReleaser and publish archives and deb/rpm/apk.
5. Verify assets and checksums.

Optional (future): sign artifacts and checksums with cosign; push Homebrew/Scoop/AUR.


