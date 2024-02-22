package ledger

import "github.com/CreatureDev/xrpl-go/model/transactions/types"

type PayChannel struct {
	Account           types.Address           `json:",omitempty"`
	Amount            types.XRPCurrencyAmount `json:",omitempty"`
	Balance           types.XRPCurrencyAmount `json:",omitempty"`
	CancelAfter       uint                    `json:",omitempty"`
	Destination       types.Address           `json:",omitempty"`
	DestinationTag    uint                    `json:",omitempty"`
	DestinationNode   string                  `json:",omitempty"`
	Expiration        uint                    `json:",omitempty"`
	Flags             *types.Flag             `json:",omitempty"`
	LedgerEntryType   LedgerEntryType         `json:",omitempty"`
	OwnerNode         string                  `json:",omitempty"`
	PreviousTxnID     types.Hash256           `json:",omitempty"`
	PreviousTxnLgrSeq uint32                  `json:",omitempty"`
	PublicKey         string                  `json:",omitempty"`
	SettleDelay       uint                    `json:",omitempty"`
	SourceTag         uint                    `json:",omitempty"`
}

func (*PayChannel) EntryType() LedgerEntryType {
	return PayChannelEntry
}
