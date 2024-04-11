package client_test

import (
	"fmt"
	"os"
	"testing"

	addresscodec "github.com/CreatureDev/xrpl-go/address-codec"
	"github.com/CreatureDev/xrpl-go/client"
	jsonrpcclient "github.com/CreatureDev/xrpl-go/client/jsonrpc"
	"github.com/CreatureDev/xrpl-go/keypairs"
	"github.com/CreatureDev/xrpl-go/model/client/faucet"
	"github.com/CreatureDev/xrpl-go/model/transactions/types"
	"github.com/stretchr/testify/assert"
)

var cl *client.XRPLClient

func TestFundAccount(t *testing.T) {
	acc, _, _ := generateTestAccount(t)
	resp, _, err := cl.Faucet.FundAccount(&faucet.FundAccountRequest{Destination: acc})
	assert.Nil(t, err)
	assert.Equal(t, acc, resp.Account.Address)
}

func init() {
	conf, err := client.NewJsonRpcConfig("https://s.altnet.rippletest.net:51234/")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	rpccl := jsonrpcclient.NewJsonRpcClient(conf)
	cl = client.NewXRPLClient(rpccl)
}

func generateTestAccount(t *testing.T) (types.Address, string, string) {
	seed, _ := keypairs.GenerateSeed("", addresscodec.ED25519)
	priv, pub, _ := keypairs.DeriveKeypair(seed, false)
	acc, _ := keypairs.DeriveClassicAddress(pub)
	return acc, priv, pub
}
