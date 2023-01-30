package ledger

import "fmt"

type LedgerEntryType string

const (
	AccountRootEntry    LedgerEntryType = "AccountRoot"
	AmendmentsEntry                     = "Amendments"
	CheckEntry                          = "Check"
	DepositPreauthEntry                 = "DepositPreauth"
	DirectoryNodeEntry                  = "DirectoryNode"
	EscrowEntry                         = "Escrow"
	FeeSettingsEntry                    = "FeeSettings"
	LedgerHashesEntry                   = "LedgerHashes"
	NegativeUNLEntry                    = "NegativeUNL"
	NFTokenOfferEntry                   = "NFTokenOffer"
	OfferEntry                          = "Offer"
	PayChannelEntry                     = "PayChannel"
	RippleStateEntry                    = "RippleState"
	SignerListEntry                     = "SignerList"
	TicketEntry                         = "Ticket"
)

type LedgerObject interface {
	LedgerEntryType() LedgerEntryType
}

func UnmarshalLedgerObject(data []byte) (LedgerObject, error) {
	// TODO
	return nil, fmt.Errorf("LedgerObject parsing unimplmeneted")
}
