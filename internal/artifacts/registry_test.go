package artifacts

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanRegistryImage_InvalidRef(t *testing.T) {
	err := ScanRegistryImage("invalid reference", Limits{}, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid image reference")
}

// Note: Valid registry tests require network and valid credentials or a public image.
// We skip them here to keep unit tests fast and hermetic.
