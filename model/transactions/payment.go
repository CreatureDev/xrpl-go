package transactions

type Payment struct {
	BaseTx
	Amount         CurrencyAmount
	Destination    Address
	DestinationTag uint           `json:",omitempty"`
	InvoiceID      uint           `json:",omitempty"`
	Paths          [][]PathStep   `json:",omitempty"`
	SendMax        CurrencyAmount `json:",omitempty"`
	DeliverMin     CurrencyAmount `json:",omitempty"`
}

func (*Payment) TxType() TxType {
	return PaymentTx
}
