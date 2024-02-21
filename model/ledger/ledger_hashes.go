package ledger

import "github.com/CreatureDev/xrpl-go/model/transactions/types"

type LedgerHashes struct {
	FirstLedgerSequence uint32          `json:",omitempty"`
	Flags               *types.Flag     `json:",omitempty"`
	Hashes              []types.Hash256 `json:",omitempty"`
	LastLedgerSequence  uint32          `json:",omitempty"`
	LedgerEntryType     LedgerEntryType `json:",omitempty"`
}

func (*LedgerHashes) EntryType() LedgerEntryType {
	return LedgerHashesEntry
}
