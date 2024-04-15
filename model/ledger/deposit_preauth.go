package ledger

import (
	"github.com/CreatureDev/xrpl-go/model/transactions/types"
)

type DepositPreauthObj struct {
	Account           types.Address   `json:",omitempty"`
	Authorize         types.Address   `json:",omitempty"`
	Flags             *types.Flag     `json:",omitempty"`
	LedgerEntryType   LedgerEntryType `json:",omitempty"`
	OwnerNode         string          `json:",omitempty"`
	PreviousTxnID     types.Hash256   `json:",omitempty"`
	PreviousTxnLgrSeq uint32          `json:",omitempty"`
	Index             types.Hash256   `json:"index,omitempty"`
}

func (*DepositPreauthObj) EntryType() LedgerEntryType {
	return DepositPreauthObjEntry
}
