package ledger

import "github.com/CreatureDev/xrpl-go/model/transactions/types"

type FeeSettings struct {
	BaseFee           string          `json:",omitempty"`
	Flags             *types.Flag     `json:",omitempty"`
	LedgerEntryType   LedgerEntryType `json:",omitempty"`
	ReferenceFeeUnits uint            `json:",omitempty"`
	ReserveBase       uint            `json:",omitempty"`
	ReserveIncrement  uint            `json:",omitempty"`
}

func (*FeeSettings) EntryType() LedgerEntryType {
	return FeeSettingsEntry
}
