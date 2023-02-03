package account

import (
	"encoding/json"

	. "github.com/xyield/xrpl-go/model/client/common"
	. "github.com/xyield/xrpl-go/model/transactions/types"
)

type AccountNftsRequest struct {
	Account     Address         `json:"account"`
	LedgerIndex LedgerSpecifier `json:"ledger_index,omitempty"`
	LedgerHash  LedgerHash      `json:"ledger_hash,omitempty"`
	Limit       int             `json:"limit,omitempty"`
	Marker      interface{}     `json:"marker,omitempty"`
}

func (r *AccountNftsRequest) UnmarshalJSON(data []byte) error {
	type anrHelper struct {
		Account     Address         `json:"account"`
		LedgerIndex json.RawMessage `json:"ledger_index,omitempty"`
		LedgerHash  LedgerHash      `json:"ledger_hash,omitempty"`
		Limit       int             `json:"limit,omitempty"`
		Marker      interface{}     `json:"marker,omitempty"`
	}
	var h anrHelper
	if err := json.Unmarshal(data, &h); err != nil {
		return err
	}
	*r = AccountNftsRequest{
		Account:    h.Account,
		LedgerHash: h.LedgerHash,
		Limit:      h.Limit,
		Marker:     h.Marker,
	}

	i, err := UnmarshalLedgerSpecifier(h.LedgerIndex)
	if err != nil {
		return err
	}
	r.LedgerIndex = i
	return nil
}
