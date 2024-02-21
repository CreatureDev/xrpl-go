package ledger

import "github.com/CreatureDev/xrpl-go/model/transactions/types"

type NegativeUNL struct {
	DisabledValidators  []DisabledValidatorEntry `json:",omitempty"`
	Flags               *types.Flag              `json:",omitempty"`
	LedgerEntryType     LedgerEntryType          `json:",omitempty"`
	ValidatorToDisable  string                   `json:",omitempty"`
	ValidatorToReEnable string                   `json:",omitempty"`
}

func (*NegativeUNL) EntryType() LedgerEntryType {
	return NegativeUNLEntry
}

type DisabledValidatorEntry struct {
	DisabledValidator DisabledValidator
}

type DisabledValidator struct {
	FirstLedgerSequence uint32
	PublicKey           string
}
