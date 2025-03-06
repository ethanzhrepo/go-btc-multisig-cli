package util

import (
	"os"
	"testing"
)

func TestGetUTXOs(t *testing.T) {
	// 使用环境变量获取测试网节点信息
	// 如果没有设置，使用默认值或跳过测试
	rpcURL := os.Getenv("BTC_TESTNET_RPC_URL")
	if rpcURL == "" {
		// rpcURL = "https://bitcoin-testnet-rpc.publicnode.com" // 一个公共测试网节点，仅用于测试
		// rpcURL = "https://docs-demo.btc.quiknode.pro"
		rpcURL = "http://nx:18332"
	}

	rpcUser := "test"
	rpcPass := "test123"

	// 测试地址
	testAddress := "myU45BxXdvsLJSBExa4AAVX6ts4hNUcKip"

	// 调用 GetUTXOs 函数
	utxos, err := GetUTXOs(testAddress, rpcURL, rpcUser, rpcPass)

	// 检查是否有错误
	if err != nil {
		// 如果错误来自认证问题，将其视为跳过测试而非失败
		if rpcUser == "" || rpcPass == "" {
			t.Skipf("Skipping test due to missing credentials: %v", err)
		} else {
			t.Fatalf("Failed to get UTXOs: %v", err)
		}
	}

	// 打印找到的 UTXO 数量
	t.Logf("Found %d UTXOs for address %s", len(utxos), testAddress)

	// 打印 UTXO 详情
	for i, utxo := range utxos {
		t.Logf("UTXO #%d:", i+1)
		t.Logf("  TxID: %s", utxo.TxID)
		t.Logf("  Vout: %d", utxo.Vout)
		t.Logf("  Amount: %f BTC (%d satoshis)", utxo.Amount, utxo.AmountSatoshis)
		t.Logf("  Confirmations: %d", utxo.Confirmations)
		t.Logf("  Spendable: %t", utxo.Spendable)
	}

	// 基本验证
	if len(utxos) > 0 {
		// 检查第一个 UTXO 的基本属性
		firstUTXO := utxos[0]

		// 验证地址
		if firstUTXO.Address != testAddress {
			t.Errorf("Expected address %s, got %s", testAddress, firstUTXO.Address)
		}

		// 验证 txid 非空
		if firstUTXO.TxID == "" {
			t.Error("Expected non-empty TxID")
		}

		// 验证金额计算是否正确
		expectedSatoshis := int64(firstUTXO.Amount * 100000000)
		if firstUTXO.AmountSatoshis != expectedSatoshis {
			t.Errorf("Expected %d satoshis, got %d", expectedSatoshis, firstUTXO.AmountSatoshis)
		}
	} else {
		t.Log("No UTXOs found for this address, which is valid but prevents further testing")
	}
}
