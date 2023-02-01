package transactions

type EscrowFinish struct {
	BaseTx
	Owner         Address
	OfferSequence uint
	Condition     []byte `json:",omitempty"`
	Fulfillment   []byte `json:",omitempty"`
}

func (*EscrowFinish) TxType() TxType {
	return EscrowFinishTx
}
