package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethanzhrepo/go-btc-multisig-cli/util"
	"github.com/spf13/cobra"
)

// MultisigTx 表示多签交易的结构
type MultisigTx struct {
	Version      int                 `json:"version"`
	TxID         string              `json:"txid"`
	UnsignedTx   string              `json:"unsigned_tx"`
	SignedTx     string              `json:"signed_tx,omitempty"`
	Inputs       []MultisigTxInput   `json:"inputs"`
	Outputs      []MultisigTxOutput  `json:"outputs"`
	Signatures   map[string][]string `json:"signatures,omitempty"`
	IsComplete   bool                `json:"is_complete"`
	RequiredSigs int                 `json:"required_sigs"`
	TotalSigs    int                 `json:"total_sigs"`
	Network      string              `json:"network"`
}

// MultisigTxInput 表示多签交易的输入
type MultisigTxInput struct {
	TxID          string   `json:"txid"`
	Vout          uint32   `json:"vout"`
	Amount        int64    `json:"amount"`
	ScriptPubKey  string   `json:"script_pub_key"`
	RedeemScript  string   `json:"redeem_script"`
	WitnessScript string   `json:"witness_script,omitempty"`
	Address       string   `json:"address"`
	Signatures    []string `json:"signatures,omitempty"`
}

// MultisigTxOutput 表示多签交易的输出
type MultisigTxOutput struct {
	Address string `json:"address"`
	Amount  int64  `json:"amount"`
}

// PrivateKeyFile 表示加密的私钥文件
type PrivateKeyFile struct {
	EncryptedKey string `json:"encrypted_key"`
	PublicKey    string `json:"public_key"`
}

// 交易初始化命令
func InitTxCmd() *cobra.Command {
	var toAddress string
	var amount int64
	var inputWallet string
	var feeRate int64

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a multisig transaction",
		Long:  "Initialize a new multisig transaction with specified parameters",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 解析输入路径
			method, path, err := util.ParseStoragePath(inputWallet)
			if err != nil {
				return fmt.Errorf("invalid input wallet path: %v", err)
			}

			// 读取钱包文件
			var walletData []byte
			switch method {
			case "fs":
				walletData, err = os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("failed to read wallet file: %v", err)
				}
			case "googledrive":
				walletData, err = util.DownloadFromGoogleDrive(path)
				if err != nil {
					return fmt.Errorf("failed to download from Google Drive: %v", err)
				}
			case "dropbox":
				walletData, err = util.DownloadFromDropbox(path)
				if err != nil {
					return fmt.Errorf("failed to download from Dropbox: %v", err)
				}
			case "onedrive":
				walletData, err = util.DownloadFromOneDrive(path)
				if err != nil {
					return fmt.Errorf("failed to download from OneDrive: %v", err)
				}
			default:
				return fmt.Errorf("unsupported storage method: %s", method)
			}

			// 解析钱包数据
			var wallet MultiSigWallet
			if err := json.Unmarshal(walletData, &wallet); err != nil {
				return fmt.Errorf("failed to parse wallet data: %v", err)
			}

			// 选择网络
			var params *chaincfg.Params
			if wallet.TestNet {
				params = &chaincfg.TestNet3Params
			} else {
				params = &chaincfg.MainNetParams
			}

			// 验证目标地址
			destAddress, err := btcutil.DecodeAddress(toAddress, params)
			if err != nil {
				return fmt.Errorf("invalid destination address: %v", err)
			}

			// 获取多签地址
			var sourceAddr string
			switch strings.ToLower(wallet.Type) {
			case "p2sh":
				sourceAddr = wallet.P2SHAddress
			case "p2wsh":
				sourceAddr = wallet.P2WSHAddress
			case "p2sh-p2wsh":
				sourceAddr = wallet.P2SHP2WSHAddress
			default:
				sourceAddr = wallet.Address
			}

			fmt.Printf("Source address: %s\n", sourceAddr)
			fmt.Printf("Destination address: %s\n", destAddress.EncodeAddress())
			fmt.Printf("Amount: %d satoshis\n", amount)

			// 创建空交易结构
			// 注意：这里只是演示，实际应用中你需要从UTXO数据源获取未花费输出
			tx := wire.NewMsgTx(2) // 版本2

			// 模拟一个输入（实际应用中应该从区块链查询）
			// 这个UTXO需要你手动填入正确的txId和vout
			previousTxID := "0000000000000000000000000000000000000000000000000000000000000000"
			vout := uint32(0)

			fmt.Println("\nFor demonstration, we'll create a dummy transaction.")
			fmt.Println("In a real application, you'd need to provide actual UTXO information:")

			// 让用户输入实际的交易ID和输出索引
			fmt.Print("Enter previous transaction ID: ")
			fmt.Scanln(&previousTxID)

			fmt.Print("Enter previous output index (vout): ")
			fmt.Scanln(&vout)

			fmt.Print("Enter UTXO amount (in satoshis): ")
			var utxoAmount int64
			fmt.Scanln(&utxoAmount)

			if utxoAmount <= amount {
				return fmt.Errorf("UTXO amount (%d) must be greater than output amount (%d) to cover fees", utxoAmount, amount)
			}

			// 解析交易ID
			txHash, err := hex.DecodeString(previousTxID)
			if err != nil {
				return fmt.Errorf("invalid transaction ID: %v", err)
			}

			// 创建交易输入
			prevOutPoint := wire.NewOutPoint((*chainhash.Hash)(txHash), vout)
			txIn := wire.NewTxIn(prevOutPoint, nil, nil)
			tx.AddTxIn(txIn)

			// 创建交易输出
			destScript, err := txscript.PayToAddrScript(destAddress)
			if err != nil {
				return fmt.Errorf("failed to create output script: %v", err)
			}
			tx.AddTxOut(wire.NewTxOut(amount, destScript))

			// 计算找零（减去网络费用）
			// 实际应用中，费用计算应该基于交易大小和网络状态
			// 这里使用简单估计：费用 = 输入金额 - 输出金额 - 找零金额
			changeAmount := utxoAmount - amount - feeRate*200 // 粗略估计200字节的交易大小
			if changeAmount < 0 {
				return fmt.Errorf("insufficient funds for fees (estimated %d satoshis)", feeRate*200)
			}

			// 如果有找零，添加找零输出
			if changeAmount > 0 {
				// 找零地址与来源地址相同
				sourceAddress, err := btcutil.DecodeAddress(sourceAddr, params)
				if err != nil {
					return fmt.Errorf("invalid source address: %v", err)
				}

				changeScript, err := txscript.PayToAddrScript(sourceAddress)
				if err != nil {
					return fmt.Errorf("failed to create change script: %v", err)
				}
				tx.AddTxOut(wire.NewTxOut(changeAmount, changeScript))
			}

			// 序列化交易
			var txBuf bytes.Buffer
			if err := tx.Serialize(&txBuf); err != nil {
				return fmt.Errorf("failed to serialize transaction: %v", err)
			}

			// 解码赎回脚本
			_, err = hex.DecodeString(wallet.RedeemScript)
			if err != nil {
				return fmt.Errorf("failed to decode redeem script: %v", err)
			}

			// 创建交易数据结构
			msigTx := MultisigTx{
				Version:    1,
				TxID:       tx.TxHash().String(),
				UnsignedTx: base64.StdEncoding.EncodeToString(txBuf.Bytes()),
				Inputs: []MultisigTxInput{
					{
						TxID:          previousTxID,
						Vout:          vout,
						Amount:        utxoAmount,
						ScriptPubKey:  wallet.ScriptPubKey,
						RedeemScript:  wallet.RedeemScript,
						WitnessScript: wallet.WitnessScript,
						Address:       sourceAddr,
					},
				},
				Outputs: []MultisigTxOutput{
					{
						Address: destAddress.EncodeAddress(),
						Amount:  amount,
					},
				},
				Signatures:   make(map[string][]string),
				IsComplete:   false,
				RequiredSigs: wallet.RequiredSignatures,
				TotalSigs:    wallet.TotalKeys,
				Network:      wallet.Network,
			}

			// 如果有找零，添加到输出
			if changeAmount > 0 {
				msigTx.Outputs = append(msigTx.Outputs, MultisigTxOutput{
					Address: sourceAddr,
					Amount:  changeAmount,
				})
			}

			// 序列化为JSON
			txJSON, err := json.MarshalIndent(msigTx, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to serialize transaction data: %v", err)
			}

			// 输出到控制台
			fmt.Println("\n========== UNSIGNED TRANSACTION ==========")
			fmt.Println(string(txJSON))
			fmt.Println("==========================================")
			fmt.Println("\nShare this transaction data with co-signers.")
			fmt.Println("Use the 'sign' command to sign this transaction.")

			return nil
		},
	}

	// 添加命令行参数
	cmd.Flags().StringVar(&toAddress, "to", "", "Destination Bitcoin address")
	cmd.Flags().Int64Var(&amount, "amount", 0, "Amount to send (in satoshis)")
	cmd.Flags().StringVar(&inputWallet, "input", "", "Multisig wallet file path (format: 'method:path')")
	cmd.Flags().Int64Var(&feeRate, "feeRate", 1, "Fee rate in satoshis per byte")

	// 标记必须的参数
	cmd.MarkFlagRequired("to")
	cmd.MarkFlagRequired("amount")
	cmd.MarkFlagRequired("input")

	return cmd
}

// TxCmd 返回 tx 命令
func TxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tx",
		Short: "Manage multisig transactions",
		Long:  "Create and sign Bitcoin multisig transactions",
	}

	// 添加子命令
	cmd.AddCommand(
		InitTxCmd(),
		// 签名功能暂时移除
	)

	return cmd
}
