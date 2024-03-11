package websocket

import (
	"encoding/json"

	"github.com/CreatureDev/xrpl-go/client"
	"github.com/mitchellh/mapstructure"
)

func (c *WebsocketClient) formatRequest(req client.XRPLRequest, id int, marker any) ([]byte, error) {
	m := make(map[string]any)
	m["id"] = id
	if method := req.Method(); method != "" {
		m["command"] = method
	}
	if marker != nil {
		m["marker"] = marker
	}
	dec, _ := mapstructure.NewDecoder(&mapstructure.DecoderConfig{TagName: "json", Result: &m})
	err := dec.Decode(req)
	if err != nil {
		return nil, err
	}

	return json.Marshal(m)
}
