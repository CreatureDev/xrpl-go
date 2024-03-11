package client

import (
	"github.com/CreatureDev/xrpl-go/model/client/faucet"
)

type Faucet interface {
	FundAccount(*faucet.FundAccountRequest) (*faucet.FundAccountResponse, XRPLResponse, error)
}

type faucetImpl struct {
	client Client
}

func (f *faucetImpl) FundAccount(req *faucet.FundAccountRequest) (*faucet.FundAccountResponse, XRPLResponse, error) {
	res, err := f.client.SendRequest(req)
	if err != nil {
		return nil, nil, err
	}
	var far faucet.FundAccountResponse
	err = res.GetResult(&far)
	if err != nil {
		return nil, nil, err
	}
	return &far, res, nil
}
