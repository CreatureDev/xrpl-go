package ledger

import "github.com/CreatureDev/xrpl-go/model/transactions/types"

type Ticket struct {
	Account           types.Address   `json:",omitempty"`
	Flags             *types.Flag     `json:",omitempty"`
	LedgerEntryType   LedgerEntryType `json:",omitempty"`
	OwnerNode         string          `json:",omitempty"`
	PreviousTxnID     types.Hash256   `json:",omitempty"`
	PreviousTxnLgrSeq uint32          `json:",omitempty"`
	TicketSequence    uint32          `json:",omitempty"`
}

func (*Ticket) EntryType() LedgerEntryType {
	return TicketEntry
}
