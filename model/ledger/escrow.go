package ledger

import (
	"github.com/CreatureDev/xrpl-go/model/transactions/types"
)

type Escrow struct {
	Account           types.Address           `json:",omitempty"`
	Amount            types.XRPCurrencyAmount `json:",omitempty"`
	CancelAfter       uint                    `json:",omitempty"`
	Condition         string                  `json:",omitempty"`
	Destination       types.Address           `json:",omitempty"`
	DestinationNode   string                  `json:",omitempty"`
	DestinationTag    uint                    `json:",omitempty"`
	FinishAfter       uint                    `json:",omitempty"`
	Flags             *types.Flag             `json:",omitempty"`
	LedgerEntryType   LedgerEntryType         `json:",omitempty"`
	OwnerNode         string                  `json:",omitempty"`
	PreviousTxnID     types.Hash256           `json:",omitempty"`
	PreviousTxnLgrSeq uint32                  `json:",omitempty"`
	SourceTag         uint                    `json:",omitempty"`
}

func (*Escrow) EntryType() LedgerEntryType {
	return EscrowEntry
}
