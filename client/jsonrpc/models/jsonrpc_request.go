package jsonrpcmodels

type JsonRpcRequest struct {
	Method string         `json:"method,omitempty"`
	Params [1]interface{} `json:"params,omitempty"`
}
