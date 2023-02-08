package account

import (
	"testing"

	. "github.com/xyield/xrpl-go/model/client/common"
	"github.com/xyield/xrpl-go/test"
)

func TestAccountCurrenciesRequest(t *testing.T) {
	s := AccountCurrenciesRequest{
		Account:     "r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",
		Strict:      true,
		LedgerIndex: LedgerIndex(1234),
	}

	j := `{
	"account": "r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",
	"ledger_index": 1234,
	"strict": true
}`
	if err := test.SerializeAndDeserialize(s, j); err != nil {
		t.Error(err)
	}
}