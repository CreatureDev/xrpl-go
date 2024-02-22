package ledger

import (
	"github.com/CreatureDev/xrpl-go/model/transactions/types"
)

type Amendments struct {
	Amendments      []types.Hash256 `json:",omitempty"`
	Flags           *types.Flag     `json:",omitempty"`
	LedgerEntryType LedgerEntryType `json:",omitempty"`
	Majorities      []MajorityEntry `json:",omitempty"`
}

func (*Amendments) EntryType() LedgerEntryType {
	return AmendmentsEntry
}

type MajorityEntry struct {
	Majority Majority
}

type Majority struct {
	Amendment types.Hash256
	CloseTime uint
}
