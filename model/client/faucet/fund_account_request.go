package faucet

import (
	"fmt"

	"github.com/CreatureDev/xrpl-go/model/transactions/types"
)

type FundAccountRequest struct {
	Destination types.Address `json:"destination"`
}

func (*FundAccountRequest) Method() string {
	return ""
}

func (f *FundAccountRequest) Validate() error {
	if err := f.Destination.Validate(); err != nil {
		return fmt.Errorf("faucet fund account: %w", err)
	}
	return nil
}
