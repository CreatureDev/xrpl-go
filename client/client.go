package client

import (
	"fmt"

	"github.com/CreatureDev/xrpl-go/model/client/account"
	"github.com/CreatureDev/xrpl-go/model/client/server"
	"github.com/CreatureDev/xrpl-go/model/transactions"
	"github.com/CreatureDev/xrpl-go/model/transactions/types"
)

type Client interface {
	SendRequest(req XRPLRequest) (XRPLResponse, error)
	Address() string
	Faucet() string
}

type XRPLClient struct {
	client       Client
	Account      Account
	Channel      Channel
	Ledger       Ledger
	Path         Path
	Subscription Subscription
	Transaction  Transaction
	Server       Server
	Clio         Clio
	Faucet       Faucet
}

type XRPLRequest interface {
	Method() string
	Validate() error
}

type XRPLResponse interface {
	GetResult(v any) error
	GetError() error
}

type XRPLResponseWarning struct {
	Id      int    `json:"id"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func NewXRPLClient(cl Client) *XRPLClient {
	return &XRPLClient{
		client:       cl,
		Account:      &accountImpl{client: cl},
		Channel:      &channelImpl{client: cl},
		Ledger:       &ledgerImpl{client: cl},
		Path:         &pathImpl{client: cl},
		Subscription: &subscriptionImpl{client: cl},
		Transaction:  &transactionImpl{client: cl},
		Clio:         &clioImpl{client: cl},
		Faucet:       &faucetImpl{client: cl},
	}
}

func (c *XRPLClient) Client() Client {
	return c.client
}

func (c *XRPLClient) AutofillTx(acc types.Address, tx transactions.Tx) error {
	if tx == nil {
		return nil
	}
	accInfoRequest := &account.AccountInfoRequest{
		Account: acc,
	}
	b := transactions.BaseTxForTransaction(tx)
	if b == nil {
		base, ok := tx.(*transactions.BaseTx)
		if !ok {
			return fmt.Errorf("unknown transaction type")
		}
		b = base
	}
	accInfo, _, err := c.Account.AccountInfo(accInfoRequest)
	if err != nil {
		return fmt.Errorf("fetching account info: %w", err)
	}
	serverInfo, _, err := c.Server.ServerInfo(&server.ServerInfoRequest{})

	b.Sequence = accInfo.AccountData.Sequence
	b.TransactionType = tx.TxType()
	b.Fee = types.XRPDropsFromFloat(serverInfo.Info.ValidatedLedger.BaseFeeXRP)

	return nil
}
