package account

import (
	"encoding/json"
	"fmt"

	"github.com/CreatureDev/xrpl-go/model/client/common"
	"github.com/CreatureDev/xrpl-go/model/transactions/types"
)

type AccountInfoRequest struct {
	Account     types.Address          `json:"account"`
	LedgerIndex common.LedgerSpecifier `json:"ledger_index,omitempty"`
	LedgerHash  common.LedgerHash      `json:"ledger_hash,omitempty"`
	Queue       bool                   `json:"queue,omitempty"`
	SignerList  bool                   `json:"signer_list,omitempty"`
	Strict      bool                   `json:"strict,omitempty"`
}

func (*AccountInfoRequest) Method() string {
	return "account_info"
}

func (r *AccountInfoRequest) Validate() error {
	if err := r.Account.Validate(); err != nil {
		return fmt.Errorf("account info request: %w", err)
	}

	return nil
}

func (r *AccountInfoRequest) UnmarshalJSON(data []byte) error {
	type airHelper struct {
		Account     types.Address     `json:"account"`
		LedgerIndex json.RawMessage   `json:"ledger_index,omitempty"`
		LedgerHash  common.LedgerHash `json:"ledger_hash,omitempty"`
		Queue       bool              `json:"queue,omitempty"`
		SignerList  bool              `json:"signer_list,omitempty"`
		Strict      bool              `json:"strict,omitempty"`
	}
	var h airHelper
	if err := json.Unmarshal(data, &h); err != nil {
		return err
	}
	*r = AccountInfoRequest{
		Account:    h.Account,
		LedgerHash: h.LedgerHash,
		Queue:      h.Queue,
		SignerList: h.SignerList,
		Strict:     h.Strict,
	}

	i, err := common.UnmarshalLedgerSpecifier(h.LedgerIndex)
	if err != nil {
		return err
	}
	r.LedgerIndex = i
	return nil
}
