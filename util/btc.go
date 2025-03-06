package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// UTXO 表示未花费的交易输出
type UTXO struct {
	TxID           string  `json:"txid"`
	Vout           uint32  `json:"vout"`
	Address        string  `json:"address"`
	ScriptPubKey   string  `json:"scriptPubKey"`
	Amount         float64 `json:"amount"` // 以BTC为单位
	Confirmations  int     `json:"confirmations"`
	RedeemScript   string  `json:"redeemScript,omitempty"`
	WitnessScript  string  `json:"witnessScript,omitempty"`
	Spendable      bool    `json:"spendable"`
	Solvable       bool    `json:"solvable"`
	Desc           string  `json:"desc,omitempty"`
	Safe           bool    `json:"safe"`
	AmountSatoshis int64   `json:"amount_satoshis"` // 自动计算的satoshi值
}

// RPCRequest 表示Bitcoin RPC请求
type RPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

// RPCResponse 表示Bitcoin RPC响应
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCError       `json:"error,omitempty"`
	ID      int             `json:"id"`
}

// RPCError 表示Bitcoin RPC错误
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// GetUTXOs 获取指定地址的UTXO列表
func GetUTXOs(address string, rpcURL string, rpcUser string, rpcPass string) ([]UTXO, error) {
	// 构建RPC请求
	// listunspent 参数: 最小确认, 最大确认, 地址列表
	request := RPCRequest{
		JSONRPC: "1.0",
		Method:  "listunspent",
		Params:  []interface{}{1, 9999999, []string{address}},
		ID:      1,
	}

	// 序列化请求为JSON
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal request failed: %v", err)
	}

	// 创建HTTP请求
	req, err := http.NewRequest("POST", rpcURL, bytes.NewBuffer(requestJSON))
	if err != nil {
		return nil, fmt.Errorf("create HTTP request failed: %v", err)
	}

	// 设置Basic认证
	if rpcUser != "" && rpcPass != "" {
		req.SetBasicAuth(rpcUser, rpcPass)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	// 检查HTTP状态
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	// 读取响应数据
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %v", err)
	}

	// 解析响应
	var rpcResponse RPCResponse
	if err := json.Unmarshal(body, &rpcResponse); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %v", err)
	}

	// 检查RPC错误
	if rpcResponse.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResponse.Error.Code, rpcResponse.Error.Message)
	}

	// 解析UTXO列表
	var utxos []UTXO
	if err := json.Unmarshal(rpcResponse.Result, &utxos); err != nil {
		return nil, fmt.Errorf("unmarshal UTXOs failed: %v", err)
	}

	// 计算satoshi值
	for i := range utxos {
		utxos[i].AmountSatoshis = int64(utxos[i].Amount * 100000000)
	}

	return utxos, nil
}
