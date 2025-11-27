package artifacts

import (
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ScanRegistryImage downloads and streams layers from a remote registry without pulling the full image to disk.
// It uses the local Docker credentials (if available) for authentication.
func ScanRegistryImage(imageRef string, limits Limits, emit func(path string, data []byte), stats *Stats) error {
	// Parse the image reference (e.g., "gcr.io/my-project/image:latest")
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("invalid image reference %q: %w", imageRef, err)
	}

	// Fetch the image metadata.
	// remote.Image() uses the default keychain (e.g., ~/.docker/config.json) for auth.
	// This does NOT download the layers yet.
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return fmt.Errorf("failed to fetch image metadata for %q: %w", imageRef, err)
	}

	// Get the list of layers
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("failed to get layers for %q: %w", imageRef, err)
	}

	var decompressed int64
	var entries int

	started := time.Now()
	deadline := time.Time{}
	if limits.TimeBudget > 0 {
		deadline = started.Add(limits.TimeBudget)
	}

	// Iterate over layers and stream them
	for _, layer := range layers {
		// Check global/artifact limits before starting a layer
		if r := limitsExceededReason(limits, decompressed, entries, 0, deadline); r != "" {
			if stats != nil {
				stats.add(r)
			}
			return nil // Abort scanning this image
		}

		digest, err := layer.Digest()
		if err != nil {
			continue
		}

		rc, err := layer.Uncompressed()
		if err != nil {
			return fmt.Errorf("failed to read layer %s: %w", digest, err)
		}

		// Construct virtual path: image:tag::sha256:hash
		// Files within layer will be: image:tag::sha256:hash/path/to/file
		vp := fmt.Sprintf("%s::%s", imageRef, digest.String())

		// Use the shared tar scanner from artifacts.go
		// We pass depth=1 because the layer itself is "inside" the image
		err = scanTarReaderJoin(vp, "/", limits, &decompressed, &entries, 1, deadline, emit, rc)
		safeClose(rc)
		if err != nil {
			return err
		}
	}

	return nil
}
