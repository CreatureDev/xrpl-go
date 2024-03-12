package faucet

import "github.com/CreatureDev/xrpl-go/model/transactions/types"

type FundAccountResponse struct {
	Account FaucetAccount `json:"account"`
	Amount  uint64        `json:"amount"`
	TxHash  types.Hash128 `json:"transactionHash"`
}

type FaucetAccount struct {
	XAddress       string        `json:"xAddress"`
	ClassicAddress types.Address `json:"classicAddress"`
	Address        types.Address `json:"address"`
}
