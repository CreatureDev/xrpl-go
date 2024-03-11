package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CreatureDev/xrpl-go/model/client/faucet"
)

type Faucet interface {
	FundAccount(*faucet.FundAccountRequest) (*faucet.FundAccountResponse, XRPLResponse, error)
}

type faucetImpl struct {
	client Client
}

func (f *faucetImpl) FundAccount(req *faucet.FundAccountRequest) (*faucet.FundAccountResponse, XRPLResponse, error) {
	url := f.client.Address()
	url = strings.TrimSuffix(url, "/")
	url = url + "/accounts"
	httpClient := http.Client{Timeout: time.Duration(1) * time.Second}
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))

	if err != nil {
		return nil, nil, fmt.Errorf("building request: %w", err)
	}

	// add timeout context to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	httpReq = httpReq.WithContext(ctx)

	var response *http.Response

	response, err = httpClient.Do(httpReq)
	if err != nil || response == nil {
		return nil, nil, fmt.Errorf("sending request: %w", err)
	}

	// allow client to reuse persistant connection
	defer response.Body.Close()

	// Check for service unavailable response and retry if so
	if response.StatusCode == 503 {

		maxRetries := 3
		backoffDuration := 1 * time.Second

		for i := 0; i < maxRetries; i++ {
			time.Sleep(backoffDuration)

			// Make request again after waiting
			response, err = httpClient.Do(httpReq)
			if err != nil {
				return nil, nil, fmt.Errorf("retrying request: %w", err)
			}

			if response.StatusCode != 503 {
				break
			}

			// Increase backoff duration for the next retry
			backoffDuration *= 2
		}

		if response.StatusCode == 503 {
			// Return service unavailable error here after retry 3 times
			return nil, nil, fmt.Errorf("Server is overloaded, rate limit exceeded")
		}

	}

	b, err := io.ReadAll(response.Body)
	if err != nil || b == nil {
		return nil, nil, fmt.Errorf("reading response: %w", err)
	}
	var ret faucet.FundAccountResponse
	err = json.Unmarshal(b, &ret)
	fmt.Println(string(b))
	return &ret, nil, fmt.Errorf("unmarshal: %w", err)

}
