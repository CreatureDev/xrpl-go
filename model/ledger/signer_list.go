package ledger

import "github.com/CreatureDev/xrpl-go/model/transactions/types"

type SignerListFlags uint32

const (
	LsfOneOwnerCount SignerListFlags = 0x00010000
)

func (f SignerListFlags) ToUint() uint32 {
	return uint32(f)
}

type SignerListID uint32

type SignerList struct {
	LedgerEntryType   LedgerEntryType      `json:",omitempty"`
	Flags             *types.Flag          `json:",omitempty"`
	PreviousTxnID     string               `json:",omitempty"`
	PreviousTxnLgrSeq uint32               `json:",omitempty"`
	OwnerNode         string               `json:",omitempty"`
	SignerEntries     []SignerEntryWrapper `json:",omitempty"`
	SignerListID      *types.UInt          `json:",omitempty"`
	SignerQuorum      uint32               `json:",omitempty"`
}

type SignerEntryWrapper struct {
	SignerEntry SignerEntry
}

type SignerEntry struct {
	Account       types.Address `json:",omitempty"`
	SignerWeight  uint16        `json:",omitempty"`
	WalletLocator types.Hash256 `json:",omitempty"`
}

func (*SignerList) EntryType() LedgerEntryType {
	return SignerListEntry
}
