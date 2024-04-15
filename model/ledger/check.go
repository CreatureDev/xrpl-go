package ledger

import "github.com/CreatureDev/xrpl-go/model/transactions/types"

// TODO verify format of SendMax
type Check struct {
	Account           types.Address   `json:",omitempty"`
	Destination       types.Address   `json:",omitempty"`
	DestinationNode   string          `json:",omitempty"`
	DestinationTag    uint            `json:",omitempty"`
	Expiration        uint            `json:",omitempty"`
	Flags             *types.Flag     `json:",omitempty"`
	InvoiceID         types.Hash256   `json:",omitempty"`
	LedgerEntryType   LedgerEntryType `json:",omitempty"`
	OwnerNode         string          `json:",omitempty"`
	PreviousTxnID     types.Hash256   `json:",omitempty"`
	PreviousTxnLgrSeq uint            `json:",omitempty"`
	SendMax           string          `json:",omitempty"`
	Sequence          uint            `json:",omitempty"`
	SourceTag         uint            `json:",omitempty"`
	Index             types.Hash256   `json:"index,omitempty"`
}

func (*Check) EntryType() LedgerEntryType {
	return CheckEntry
}
