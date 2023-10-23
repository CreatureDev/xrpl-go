package transactions

import (
	"github.com/xyield/xrpl-go/model/transactions/types"
)

type EscrowCancel struct {
	BaseTx
	Owner         types.Address
	OfferSequence uint32
}

func (*EscrowCancel) TxType() TxType {
	return EscrowCancelTx
}
