package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// Config 结构体定义，包含所有配置项
type Config struct {
	RpcURL          string `json:"rpc"`
	RpcPassRequired string `json:"rpc_pass_required"`
	RpcUsername     string `json:"rpc_username"`
	RpcPassword     string `json:"rpc_password"`
	DisableTLS      string `json:"disable_tls"`
	HTTPPostMode    string `json:"http_post_mode"`
}

// RPC请求结构
type RPCRequest struct {
	JsonRPC string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

// RPC响应结构
type RPCResponse struct {
	Result struct {
		FeeRate float64  `json:"feerate"`
		Errors  []string `json:"errors,omitempty"`
	} `json:"result"`
	Error interface{} `json:"error"`
	ID    string      `json:"id"`
}

func GetGasPriceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "getGasPrice",
		Short: "Get current BTC network gas price",
		Long:  "Get current BTC network gas price from configured RPC node",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 获取配置文件路径
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %v", err)
			}
			configPath := filepath.Join(home, ".btc-multisig", "config.json")

			// 检查配置文件是否存在
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				return fmt.Errorf("config file not found. Please run 'go-btc-multisig-cli config' first to set up RPC configuration")
			}

			// 读取配置文件
			configData, err := os.ReadFile(configPath)
			if err != nil {
				return fmt.Errorf("failed to read config file: %v", err)
			}

			// 使用默认值初始化配置
			config := Config{
				HTTPPostMode: "true",  // 默认使用HTTP POST模式
				DisableTLS:   "false", // 默认启用TLS
			}

			// 从配置文件加载配置，覆盖默认值
			if err := json.Unmarshal(configData, &config); err != nil {
				return fmt.Errorf("failed to parse config file: %v", err)
			}

			// 验证RPC URL是否有效
			if config.RpcURL == "" {
				return fmt.Errorf("RPC URL not configured. Please run 'go-btc-multisig-cli config set rpc YOUR_RPC_URL' to set up RPC configuration")
			}

			// 确保RPC URL格式正确
			if !strings.HasPrefix(config.RpcURL, "http://") && !strings.HasPrefix(config.RpcURL, "https://") {
				config.RpcURL = "http://" + config.RpcURL
			}

			fmt.Println("Connecting to RPC server:", config.RpcURL)

			// 创建RPC请求
			rpcReq := RPCRequest{
				JsonRPC: "1.0",
				ID:      "btcrpc",
				Method:  "estimatesmartfee",
				Params:  []interface{}{6},
			}

			reqBody, err := json.Marshal(rpcReq)
			if err != nil {
				return fmt.Errorf("failed to create request body: %v", err)
			}

			// 创建HTTP请求
			httpReq, err := http.NewRequest("POST", config.RpcURL, bytes.NewBuffer(reqBody))
			if err != nil {
				return fmt.Errorf("failed to create HTTP request: %v", err)
			}

			// 设置请求头
			httpReq.Header.Set("Content-Type", "application/json")

			// 如果需要认证，添加认证信息
			if config.RpcPassRequired == "true" {
				httpReq.SetBasicAuth(config.RpcUsername, config.RpcPassword)
			}

			// 发送请求
			client := &http.Client{}
			fmt.Println("Sending RPC request...")
			resp, err := client.Do(httpReq)
			if err != nil {
				return fmt.Errorf("failed to send request: %v", err)
			}
			defer resp.Body.Close()

			// 读取响应
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("failed to read response: %v", err)
			}

			// 检查HTTP状态码
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("RPC server returned non-200 status: %s, body: %s", resp.Status, string(body))
			}

			// 解析响应
			var rpcResp RPCResponse
			if err := json.Unmarshal(body, &rpcResp); err != nil {
				return fmt.Errorf("failed to parse response: %v, body: %s", err, string(body))
			}

			// 检查RPC错误
			if rpcResp.Error != nil {
				return fmt.Errorf("RPC error: %v", rpcResp.Error)
			}

			// 检查费率是否可用
			if rpcResp.Result.FeeRate <= 0 {
				return fmt.Errorf("no fee estimation available (returned %f)", rpcResp.Result.FeeRate)
			}

			// 将 BTC/kB 转换为 sat/byte
			satPerByte := rpcResp.Result.FeeRate * 100000 // 转换为 sat/byte

			fmt.Printf("Current gas price (6 block target):\n")
			fmt.Printf("%.2f sat/byte\n", satPerByte)

			// 显示任何警告信息
			if len(rpcResp.Result.Errors) > 0 {
				fmt.Println("\nWarnings:", rpcResp.Result.Errors)
			}

			return nil
		},
	}

	return cmd
}
