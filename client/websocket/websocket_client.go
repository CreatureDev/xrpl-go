package websocket

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/CreatureDev/xrpl-go/client"
	"github.com/gorilla/websocket"
)

var _ client.Client = (*WebsocketClient)(nil)

var ErrIncorrectId = errors.New("incorrect id")

type WebsocketConfig struct {
	URL    string
	Faucet string
}

type WebsocketConfigOpt func(c *WebsocketConfig)

func NewWebsocketConfig(url string, opts ...WebsocketConfigOpt) (*WebsocketConfig, error) {
	if len(url) == 0 {
		return nil, fmt.Errorf("empty url provided")
	}

	if !strings.HasSuffix(url, "/") {
		url += "/"
	}

	cfg := &WebsocketConfig{
		URL:    url,
		Faucet: defaultFaucet(url),
	}

	for _, opt := range opts {
		opt(cfg)
	}
	return cfg, nil
}

type WebsocketClient struct {
	cfg       *WebsocketConfig
	idCounter atomic.Uint32
}

func (c *WebsocketClient) Address() string {
	return c.cfg.URL
}

func (c *WebsocketClient) Faucet() string {
	return c.cfg.Faucet
}

func (c *WebsocketClient) SendRequest(req client.XRPLRequest) (client.XRPLResponse, error) {
	err := req.Validate()
	if err != nil {
		return nil, err
	}

	id := c.idCounter.Add(1)

	conn, _, err := websocket.DefaultDialer.Dial(c.cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	msg, err := c.formatRequest(req, int(id), nil)
	if err != nil {
		return nil, err
	}

	err = conn.WriteMessage(websocket.TextMessage, msg)
	if err != nil {
		return nil, err
	}

	_, v, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	jDec := json.NewDecoder(bytes.NewReader(json.RawMessage(v)))
	jDec.UseNumber()
	var res WebSocketClientXrplResponse
	err = jDec.Decode(&res)
	if err != nil {
		return nil, err
	}

	if res.ID != int(id) {
		return nil, ErrIncorrectId
	}
	if err := res.GetError(); err != nil {
		return nil, err
	}

	return &res, nil
}

/*
Creates a new websocket client with cfg.

This client will open and close a websocket connection for each request.
*/
func NewWebsocketClient(cfg *WebsocketConfig) *WebsocketClient {
	return &WebsocketClient{
		cfg: cfg,
	}
}

func NewClient(cfg *WebsocketConfig) *client.XRPLClient {
	wcl := &WebsocketClient{
		cfg: cfg,
	}
	return client.NewXRPLClient(wcl)
}

func defaultFaucet(url string) string {
	if strings.Contains(url, "altnet") {
		return "https://faucet.altnet.rippletest.net/accounts"
	}
	if strings.Contains(url, "devnet") {
		return "https://faucet.devnet.rippletest.net/accounts"
	}
	return ""
}
