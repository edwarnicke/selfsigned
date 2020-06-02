package selfsigned

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// IfSpiffeUnavailableStruct - convenience Struct for IfSpiffeUnavailable
type IfSpiffeUnavailableStruct struct{}

// NewX509Source creates returns a spiffe provides X509Source if available, otherwise a new self signed X509Source.
func (o *IfSpiffeUnavailableStruct) NewX509Source(ctx context.Context) (X509Source, error) {
	if _, ok := workloadapi.GetDefaultAddress(); ok {
		source, err := workloadapi.NewX509Source(ctx)
		if err != nil {
			return nil, err
		}
		return source, nil
	}
	return NewX509Source(ctx)
}

// IfSpiffeUnvailable - return an object that, when NewX509Source(ctx) is called will return the spiffe provided Source if available, or a selfsigned SVID if not
func IfSpiffeUnvailable() *IfSpiffeUnavailableStruct {
	return &IfSpiffeUnavailableStruct{}
}
