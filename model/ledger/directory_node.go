package ledger

import (
	"github.com/CreatureDev/xrpl-go/model/transactions/types"
)

type DirectoryNode struct {
	Flags             *types.Flag     `json:",omitempty"`
	Indexes           []types.Hash256 `json:",omitempty"`
	IndexNext         string          `json:",omitempty"`
	IndexPrevious     string          `json:",omitempty"`
	LedgerEntryType   LedgerEntryType `json:",omitempty"`
	Owner             types.Address   `json:",omitempty"`
	RootIndex         types.Hash256   `json:",omitempty"`
	TakerGetsCurrency string          `json:",omitempty"`
	TakerGetsIssuer   string          `json:",omitempty"`
	TakerPaysCurrency string          `json:",omitempty"`
	TakerPaysIssuer   string          `json:",omitempty"`
	Index             types.Hash256   `json:"index,omitempty"`
}

func (*DirectoryNode) EntryType() LedgerEntryType {
	return DirectoryNodeEntry
}
