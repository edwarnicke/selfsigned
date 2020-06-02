package selfsigned_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/edwarnicke/selfsigned"
)

func TestNewX509Source(t *testing.T) {
	source, err := selfsigned.IfSpiffeUnvailable().NewX509Source(context.Background())
	require.NoError(t, err)
	require.NotNil(t, source)
}
