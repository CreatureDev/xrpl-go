package jsonrpcmodels

import (
	"encoding/json"
	"testing"

	"github.com/CreatureDev/xrpl-go/client"
	"github.com/CreatureDev/xrpl-go/model/client/account"
	"github.com/stretchr/testify/assert"
)

func TestGetResult(t *testing.T) {
	t.Run("correctly decodes", func(t *testing.T) {

		jr := JsonRpcResponse{
			Result: json.RawMessage(`{
	"account": "rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn",
	"ledger_hash": "27F530E5C93ED5C13994812787C1ED073C822BAEC7597964608F2C049C2ACD2D",
	"ledger_index": 71766343
}`),
			Warning: "none",
			Warnings: []client.XRPLResponseWarning{{
				Id:      1,
				Message: "message",
			},
			},
		}

		expected := account.AccountChannelsResponse{
			Account:     "rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn",
			LedgerHash:  "27F530E5C93ED5C13994812787C1ED073C822BAEC7597964608F2C049C2ACD2D",
			LedgerIndex: 71766343,
		}

		var acr account.AccountChannelsResponse
		err := jr.GetResult(&acr)

		assert.NoError(t, err)
		assert.Equal(t, expected, acr)
	})
	t.Run("throws error for incorrect mapping", func(t *testing.T) {

		jr := JsonRpcResponse{
			Result: json.RawMessage(`{
	"account":      123,
	"ledger_hash":  "27F530E5C93ED5C13994812787C1ED073C822BAEC7597964608F2C049C2ACD2D",
	"ledger_index": json.Number(strconv.FormatInt(71766343, 10)),
}`),
			Warning: "none",
			Warnings: []client.XRPLResponseWarning{{
				Id:      1,
				Message: "message",
			},
			},
		}

		var acr account.AccountChannelsResponse
		err := jr.GetResult(&acr)

		assert.Error(t, err)
	})
}
