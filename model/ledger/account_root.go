package ledger

import (
	"github.com/CreatureDev/xrpl-go/model/transactions/types"
)

type AccountRoot struct {
	Account           types.Address           `json:",omitempty"`
	AccountTxnID      types.Hash256           `json:",omitempty"`
	Balance           types.XRPCurrencyAmount `json:",omitempty"`
	BurnedNFTokens    uint32                  `json:",omitempty"`
	Domain            string                  `json:",omitempty"`
	EmailHash         types.Hash128           `json:",omitempty"`
	Flags             *types.Flag             `json:",omitempty"`
	LedgerEntryType   LedgerEntryType         `json:",omitempty"`
	MessageKey        string                  `json:",omitempty"`
	MintedNFTokens    uint32                  `json:",omitempty"`
	NFTokenMinter     types.Address           `json:",omitempty"`
	OwnerCount        *types.UInt             `json:",omitempty"`
	PreviousTxnID     types.Hash256           `json:",omitempty"`
	PreviousTxnLgrSeq uint32                  `json:",omitempty"`
	RegularKey        types.Address           `json:",omitempty"`
	Sequence          uint32                  `json:",omitempty"`
	TicketCount       uint32                  `json:",omitempty"`
	TickSize          uint8                   `json:",omitempty"`
	TransferRate      uint32                  `json:",omitempty"`
	Index             types.Hash256           `json:"index,omitempty"`
	// TODO determine if this is a required field
	//Index             types.Hash256 `json:"index,omitempty"`
}

func (*AccountRoot) EntryType() LedgerEntryType {
	return AccountRootEntry
}
