package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/ethanzhrepo/go-btc-multisig-cli/util"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/term"
)

// GetPublicKeyCmd 返回 getPublicKey 命令
func GetPublicKeyCmd() *cobra.Command {
	var inputPath string
	var useTestnet bool

	cmd := &cobra.Command{
		Use:   "getPublicKey",
		Short: "Get Public Key	",
		Long:  "Decrypt and get public key from encrypted wallet file",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 解析输入路径
			inputMethod, inputFilePath, err := util.ParseStoragePath(inputPath)
			if err != nil {
				return fmt.Errorf("parse input path failed: %v", err)
			}

			// 读取钱包文件
			var walletData []byte
			switch inputMethod {
			case "fs":
				walletData, err = os.ReadFile(inputFilePath)
				if err != nil {
					return fmt.Errorf("failed to read file %s: %v", inputFilePath, err)
				}
			case "googledrive":
				walletData, err = util.DownloadFromGoogleDrive(inputFilePath)
				if err != nil {
					return fmt.Errorf("failed to download from Google Drive %s: %v", inputFilePath, err)
				}
			case "dropbox":
				walletData, err = util.DownloadFromDropbox(inputFilePath)
				if err != nil {
					return fmt.Errorf("failed to download from Dropbox %s: %v", inputFilePath, err)
				}
			case "onedrive":
				walletData, err = util.DownloadFromOneDrive(inputFilePath)
				if err != nil {
					return fmt.Errorf("failed to download from OneDrive %s: %v", inputFilePath, err)
				}
			default:
				return fmt.Errorf("unsupported storage method: %s", inputMethod)
			}

			// 尝试作为WalletFile解析
			var mnemonic util.EncryptedMnemonic
			if err := json.Unmarshal(walletData, &mnemonic); err != nil {
				return fmt.Errorf("failed to parse wallet JSON: %v", err)
			}

			// 提示输入密码
			fmt.Print("Please enter the wallet password: ")
			password, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println() // 换行
			if err != nil {
				return fmt.Errorf("failed to read password: %v", err)
			}

			// 解密助记词
			mnemonicStr, err := util.DecryptMnemonic(mnemonic, string(password))
			if err != nil {
				return fmt.Errorf("failed to decrypt mnemonic: %v", err)
			}

			// 验证助记词
			if !bip39.IsMnemonicValid(mnemonicStr) {
				return fmt.Errorf("invalid mnemonic, please check the password")
			} else {
				fmt.Println("Mnemonic verified")
			}

			// 选择正确的网络参数
			var params *chaincfg.Params
			// 优先使用命令行参数指定的网络
			if useTestnet {
				params = &chaincfg.TestNet3Params
			} else {
				params = &chaincfg.MainNetParams
			}

			// 生成种子
			seed := bip39.NewSeed(mnemonicStr, "")

			// 创建主密钥
			masterKey, err := hdkeychain.NewMaster(seed, params)
			if err != nil {
				return fmt.Errorf("failed to create master key: %v", err)
			}

			// 派生路径
			path := "m/44'/0'/0'/0/0"
			if useTestnet {
				path = "m/44'/1'/0'/0/0" // 测试网
			}

			// 派生密钥
			key := masterKey
			pathParts := strings.Split(path[2:], "/") // 去掉 "m/"
			for _, part := range pathParts {
				// 处理硬化路径
				var childIndex uint32
				if strings.HasSuffix(part, "'") {
					// 硬化派生
					index := part[:len(part)-1]
					var val uint32
					fmt.Sscanf(index, "%d", &val)
					childIndex = val + hdkeychain.HardenedKeyStart
				} else {
					// 正常派生
					fmt.Sscanf(part, "%d", &childIndex)
				}

				// 派生子密钥
				key, err = key.Derive(childIndex)
				if err != nil {
					return fmt.Errorf("failed to derive path %s: %v", path, err)
				}
			}

			// 获取公钥
			pubKey, err := key.ECPubKey()
			if err != nil {
				return fmt.Errorf("failed to get public key: %v", err)
			}

			// 显示公钥信息
			fmt.Println("\nPublic key information:")
			fmt.Println("========================================")
			fmt.Printf("Derived path: %s\n", path)
			fmt.Printf("Compressed public key (Hex): %s\n", hex.EncodeToString(pubKey.SerializeCompressed()))
			fmt.Printf("Uncompressed public key (Hex): %s\n", hex.EncodeToString(pubKey.SerializeUncompressed()))

			// 输出BIP67排序需要的格式提示
			fmt.Println("\nUse this public key in multisig address generation:")
			fmt.Printf("--publicKeys parameter can be used directly: %s\n", hex.EncodeToString(pubKey.SerializeCompressed()))

			// 生成各种类型的比特币地址
			pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())

			// 1. 生成P2PKH地址 (传统地址)
			p2pkhAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, params)
			if err != nil {
				return fmt.Errorf("failed to create P2PKH address: %v", err)
			}

			// 2. 生成P2WPKH地址 (原生隔离见证地址)
			p2wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
			if err != nil {
				return fmt.Errorf("failed to create P2WPKH address: %v", err)
			}

			// 3. 生成P2SH-P2WPKH地址 (包装的隔离见证地址)
			p2shScript, err := txscript.PayToAddrScript(p2wpkhAddr)
			if err != nil {
				return fmt.Errorf("failed to create P2SH-P2WPKH script: %v", err)
			}
			scriptHash := btcutil.Hash160(p2shScript)
			p2shP2wpkhAddr, err := btcutil.NewAddressScriptHashFromHash(scriptHash, params)
			if err != nil {
				return fmt.Errorf("failed to create P2SH-P2WPKH address: %v", err)
			}

			// 获取各种地址类型的 scriptPubKey
			p2pkhScript, err := txscript.PayToAddrScript(p2pkhAddr)
			if err != nil {
				return fmt.Errorf("failed to create P2PKH script: %v", err)
			}

			p2wpkhScript, err := txscript.PayToAddrScript(p2wpkhAddr)
			if err != nil {
				return fmt.Errorf("failed to create P2WPKH script: %v", err)
			}

			p2shP2wpkhScript, err := txscript.PayToAddrScript(p2shP2wpkhAddr)
			if err != nil {
				return fmt.Errorf("failed to create P2SH-P2WPKH script: %v", err)
			}

			// 显示钱包地址信息和对应的 scriptPubKey
			fmt.Println("\nWallet addresses and scripts:")
			fmt.Println("========================================")
			fmt.Printf("Network: %s\n", networkName(params))
			fmt.Printf("P2PKH Address (Legacy):           %s\n", p2pkhAddr.EncodeAddress())
			fmt.Printf("  scriptPubKey:                   %x\n", p2pkhScript)
			fmt.Printf("P2WPKH Address (Native SegWit):   %s\n", p2wpkhAddr.EncodeAddress())
			fmt.Printf("  scriptPubKey:                   %x\n", p2wpkhScript)
			fmt.Printf("P2SH-P2WPKH Address (Nested SegWit): %s\n", p2shP2wpkhAddr.EncodeAddress())
			fmt.Printf("  scriptPubKey:                   %x\n", p2shP2wpkhScript)

			return nil
		},
	}

	// 添加参数
	cmd.Flags().StringVar(&inputPath, "input", "", "Wallet file path (format: 'method:path')")
	cmd.Flags().BoolVar(&useTestnet, "testnet", false, "Use Bitcoin testnet (overrides wallet setting)")
	cmd.MarkFlagRequired("input")

	return cmd
}

// 添加辅助函数 (如果没有的话)
func networkName(params *chaincfg.Params) string {
	if params.Name == chaincfg.MainNetParams.Name {
		return "Mainnet"
	}
	return "Testnet"
}
