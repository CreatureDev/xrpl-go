package ledger

import "github.com/CreatureDev/xrpl-go/model/transactions/types"

// TODO flags

type RippleState struct {
	Balance           types.IssuedCurrencyAmount `json:",omitempty"`
	Flags             *types.Flag                `json:",omitempty"`
	HighLimit         types.IssuedCurrencyAmount `json:",omitempty"`
	HighNode          string                     `json:",omitempty"`
	HighQualityIn     uint                       `json:",omitempty"`
	HighQualityOut    uint                       `json:",omitempty"`
	LedgerEntryType   LedgerEntryType            `json:",omitempty"`
	LowLimit          types.IssuedCurrencyAmount `json:",omitempty"`
	LowNode           string                     `json:",omitempty"`
	LowQualityIn      uint                       `json:",omitempty"`
	LowQualityOut     uint                       `json:",omitempty"`
	PreviousTxnID     types.Hash256              `json:",omitempty"`
	PreviousTxnLgrSeq uint32                     `json:",omitempty"`
	Index             types.Hash256              `json:"index,omitempty"`
}

func (*RippleState) EntryType() LedgerEntryType {
	return RippleStateEntry
}
