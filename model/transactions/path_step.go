package transactions

import (
	"github.com/CreatureDev/xrpl-go/model/transactions/types"
)

type PathStep struct {
	Account  types.Address `json:"account,omitempty"`
	Currency string        `json:"currency,omitempty"`
	Issuer   types.Address `json:"issuer,omitempty"`
}
