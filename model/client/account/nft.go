package account

import (
	. "github.com/xyield/xrpl-go/model/transactions/types"
)

const (
	Burnable     NFTokenFlag = 0x0001
	OnlyXRP                  = 0x0002
	Transferable             = 0x0008
	ReservedFlag             = 0x8000
)

type NFTokenFlag uint

type NFT struct {
	Flags        NFTokenFlag
	Issuer       Address
	NFTokenID    NFTokenID
	NFTokenTaxon uint
	URI          NFTokenURI
	NFTSerial    uint `json:"nft_serial"`
}
