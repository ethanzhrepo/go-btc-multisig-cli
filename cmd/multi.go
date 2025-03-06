package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/ethanzhrepo/go-btc-multisig-cli/util"
	"github.com/spf13/cobra"
)

// MultiSigWallet 存储多签钱包信息
type MultiSigWallet struct {
	Version            int      `json:"version"`
	CreatedAt          string   `json:"created_at"`
	Type               string   `json:"type"`
	Network            string   `json:"network"`
	M                  int      `json:"m"`
	N                  int      `json:"n"`
	PublicKeys         []string `json:"public_keys"`
	RedeemScript       string   `json:"redeem_script,omitempty"`
	WitnessScript      string   `json:"witness_script,omitempty"`
	P2SHAddress        string   `json:"p2sh_address,omitempty"`
	P2WSHAddress       string   `json:"p2wsh_address,omitempty"`
	P2SHP2WSHAddress   string   `json:"p2sh_p2wsh_address,omitempty"`
	Address            string   `json:"address"`
	ScriptPubKey       string   `json:"script_pub_key"`
	Descriptor         string   `json:"descriptor"`
	RequiredSignatures int      `json:"required_signatures"`
	TotalKeys          int      `json:"total_keys"`
	TestNet            bool     `json:"testnet"`
	P2SHDescriptor     string   `json:"p2sh_descriptor,omitempty"`
	P2WSHDescriptor    string   `json:"p2wsh_descriptor,omitempty"`
}

// GenerateMultiCmd 返回 generateMulti 命令
func GenerateMultiCmd() *cobra.Command {
	var multisigType string
	var m, n int
	var publicKeysStr string
	var outputPaths string // 接受多个输出路径的字符串
	var useTestnet bool

	cmd := &cobra.Command{
		Use:   "generateMulti",
		Short: "Generate a multisig wallet",
		Long:  "Generate a multisig wallet with specified threshold (m of n) and public keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 解析输出目标
			outputTargets, err := parseOutputTargets(outputPaths)
			if err != nil {
				return err
			}

			// 验证多签类型
			validTypes := map[string]bool{
				"p2sh":       true,
				"p2wsh":      true,
				"p2sh-p2wsh": true, // 添加嵌套SegWit
			}

			if !validTypes[strings.ToLower(multisigType)] {
				return fmt.Errorf("invalid multisig type: %s, must be one of: p2sh, p2wsh, p2sh-p2wsh", multisigType)
			}

			// 验证m和n的值
			if m <= 0 || n <= 0 || m > n {
				return fmt.Errorf("invalid threshold values: m=%d, n=%d (must satisfy: 0 < m <= n)", m, n)
			}

			// 解析公钥列表
			publicKeysList := strings.Split(publicKeysStr, ",")
			if len(publicKeysList) != n {
				return fmt.Errorf("number of public keys (%d) does not match n (%d)", len(publicKeysList), n)
			}

			// 选择网络参数
			var params *chaincfg.Params
			var networkName string
			if useTestnet {
				params = &chaincfg.TestNet3Params
				networkName = "Testnet"
			} else {
				params = &chaincfg.MainNetParams
				networkName = "Mainnet"
			}

			// 解析公钥并提供更详细的错误信息
			pubKeys := make([]*btcec.PublicKey, n)
			pubKeyHexList := make([]string, n) // 保存处理后的公钥hex

			// 在排序前检查重复公钥
			pubKeyMap := make(map[string]bool)
			for i, pkHex := range publicKeysList {
				// 修剪并规范化公钥
				trimmedPkHex := strings.TrimSpace(pkHex)

				// 验证公钥格式
				if !strings.HasPrefix(trimmedPkHex, "02") &&
					!strings.HasPrefix(trimmedPkHex, "03") &&
					!strings.HasPrefix(trimmedPkHex, "04") {
					return fmt.Errorf("invalid public key #%d: must start with 02/03 (compressed) or 04 (uncompressed)", i+1)
				}

				pkBytes, err := hex.DecodeString(trimmedPkHex)
				if err != nil {
					return fmt.Errorf("invalid public key #%d: not a valid hex string - %v", i+1, err)
				}

				// 检查公钥长度
				if len(pkBytes) != 33 && len(pkBytes) != 65 {
					return fmt.Errorf("invalid public key #%d: length is %d bytes, expected 33 (compressed) or 65 (uncompressed)",
						i+1, len(pkBytes))
				}

				// 尝试解析公钥，使用更安全的方式
				pubKey, err := btcec.ParsePubKey(pkBytes)
				if err != nil {
					// 提供更具体的错误信息
					return fmt.Errorf("failed to parse public key #%d: %v", i+1, err)
				}

				// 确保pubKey不为nil再继续
				if pubKey == nil {
					return fmt.Errorf("failed to parse public key #%d: parser returned nil", i+1)
				}

				// 统一使用压缩格式
				compressedKey := pubKey.SerializeCompressed()
				pubKeys[i] = pubKey
				pubKeyHexList[i] = hex.EncodeToString(compressedKey)

				if pubKeyMap[pubKeyHexList[i]] {
					return fmt.Errorf("duplicate public key detected at position %d", i+1)
				}
				pubKeyMap[pubKeyHexList[i]] = true
			}

			// BIP67: 按字典序排序公钥 (增强确定性多签)
			type PubKeySortable struct {
				Key *btcec.PublicKey
				Hex string
			}

			sortablePubKeys := make([]PubKeySortable, n)
			for i, key := range pubKeys {
				sortablePubKeys[i] = PubKeySortable{Key: key, Hex: pubKeyHexList[i]}
			}

			sort.Slice(sortablePubKeys, func(i, j int) bool {
				return bytes.Compare(
					sortablePubKeys[i].Key.SerializeCompressed(),
					sortablePubKeys[j].Key.SerializeCompressed(),
				) < 0
			})

			// 更新排序后的公钥
			for i, item := range sortablePubKeys {
				pubKeys[i] = item.Key
				pubKeyHexList[i] = item.Hex
			}

			// 根据多签类型生成地址
			var multiSigWallet *MultiSigWallet

			// 生成赎回脚本和见证脚本
			redeemScript, err := createMultisigScript(m, pubKeys)
			if err != nil {
				return fmt.Errorf("failed to create multisig script: %v", err)
			}

			// 检查脚本大小是否在限制范围内
			if len(redeemScript) > 520 {
				return fmt.Errorf("redeem script size (%d bytes) exceeds maximum allowed (520 bytes)", len(redeemScript))
			}

			// 计算必要的哈希和地址
			scriptHash := btcutil.Hash160(redeemScript)
			witnessScriptHash := sha256.Sum256(redeemScript)

			// 创建各种地址类型
			p2shAddr, err := btcutil.NewAddressScriptHashFromHash(scriptHash, params)
			if err != nil {
				return fmt.Errorf("failed to create P2SH address: %v", err)
			}

			// 验证P2SH地址
			if !p2shAddr.IsForNet(params) {
				return fmt.Errorf("generated P2SH address is not valid for %s", networkName)
			}

			p2wshAddr, err := btcutil.NewAddressWitnessScriptHash(witnessScriptHash[:], params)
			if err != nil {
				return fmt.Errorf("failed to create P2WSH address: %v", err)
			}

			// 验证P2WSH地址
			if !p2wshAddr.IsForNet(params) {
				return fmt.Errorf("generated P2WSH address is not valid for %s", networkName)
			}

			// 创建P2SH-P2WSH地址
			// 手动创建见证程序，替代PayToWitnessScriptHashScript
			p2wshScript := []byte{0x00, 0x20}                          // OP_0 + 32-byte push opcode
			p2wshScript = append(p2wshScript, witnessScriptHash[:]...) // Append the 32-byte hash

			p2shP2wshAddr, err := btcutil.NewAddressScriptHash(p2wshScript, params)
			if err != nil {
				return fmt.Errorf("failed to create P2SH-P2WSH address: %v", err)
			}

			// 验证P2SH-P2WSH地址
			if !p2shP2wshAddr.IsForNet(params) {
				return fmt.Errorf("generated P2SH-P2WSH address is not valid for %s", networkName)
			}

			// 创建钱包对象并根据选择类型设置地址
			multiSigWallet = &MultiSigWallet{
				Version:            1,
				CreatedAt:          time.Now().UTC().Format(time.RFC3339), // 创建时间
				Type:               strings.ToUpper(multisigType),         // 多签类型
				Network:            networkName,                           // 网络名称
				M:                  m,                                     // 所需签名数
				N:                  n,                                     // 总公钥数
				PublicKeys:         pubKeyHexList,                         // 使用排序后的公钥
				RedeemScript:       hex.EncodeToString(redeemScript),      // 赎回脚本
				WitnessScript:      hex.EncodeToString(redeemScript),      // 对于标准多签，见证脚本与赎回脚本相同
				P2SHAddress:        p2shAddr.EncodeAddress(),              // P2SH地址
				P2WSHAddress:       p2wshAddr.EncodeAddress(),             // P2WSH地址
				P2SHP2WSHAddress:   p2shP2wshAddr.EncodeAddress(),         // P2SH-P2WSH地址
				Address:            p2shAddr.EncodeAddress(),              // 钱包地址
				ScriptPubKey:       hex.EncodeToString(redeemScript),      // 脚本公钥
				Descriptor:         fmt.Sprintf("sh(multi(%d", m),         // 描述符
				RequiredSignatures: m,                                     // 所需签名数
				TotalKeys:          n,                                     // 总公钥数
				TestNet:            useTestnet,                            // 是否为测试网
			}

			// 生成描述符
			p2shDescriptor, err := buildMultisigDescriptor(m, pubKeyHexList, false)
			if err != nil {
				return fmt.Errorf("failed to build P2SH descriptor: %v", err)
			}

			p2wshDescriptor, err := buildMultisigDescriptor(m, pubKeyHexList, true)
			if err != nil {
				return fmt.Errorf("failed to build P2WSH descriptor: %v", err)
			}

			// 将描述符添加到钱包结构中
			multiSigWallet.P2SHDescriptor = p2shDescriptor
			multiSigWallet.P2WSHDescriptor = p2wshDescriptor

			// 输出多签地址信息到控制台
			fmt.Printf("\n%s Multisig Address (%s):\n", strings.ToUpper(multisigType), networkName)
			fmt.Println("========================================")

			switch strings.ToLower(multisigType) {
			case "p2sh":
				fmt.Printf("Address: %s\n", multiSigWallet.P2SHAddress)
			case "p2wsh":
				fmt.Printf("Address: %s\n", multiSigWallet.P2WSHAddress)
			case "p2sh-p2wsh":
				fmt.Printf("Address: %s\n", multiSigWallet.P2SHP2WSHAddress)
			}

			fmt.Printf("Type: %s\n", multiSigWallet.Type)
			fmt.Printf("Threshold: %d of %d\n", multiSigWallet.M, multiSigWallet.N)
			fmt.Printf("Public Keys (BIP67 sorted):\n")
			for i, pk := range multiSigWallet.PublicKeys {
				fmt.Printf("  %d: %s\n", i+1, pk)
			}
			fmt.Printf("Redeem Script: %s\n", multiSigWallet.RedeemScript)
			fmt.Printf("P2SH Descriptor: %s\n", multiSigWallet.P2SHDescriptor)
			fmt.Printf("P2WSH Descriptor: %s\n", multiSigWallet.P2WSHDescriptor)

			// 根据类型创建只包含相关字段的映射
			walletMap := map[string]interface{}{
				"version":             multiSigWallet.Version,
				"created_at":          multiSigWallet.CreatedAt,
				"type":                multiSigWallet.Type,
				"network":             multiSigWallet.Network,
				"m":                   multiSigWallet.M,
				"n":                   multiSigWallet.N,
				"public_keys":         multiSigWallet.PublicKeys,
				"required_signatures": multiSigWallet.RequiredSignatures,
				"total_keys":          multiSigWallet.TotalKeys,
				"testnet":             multiSigWallet.TestNet,
			}

			// 根据类型添加特定字段
			switch strings.ToLower(multisigType) {
			case "p2sh":
				walletMap["redeem_script"] = multiSigWallet.RedeemScript
				walletMap["p2sh_address"] = multiSigWallet.P2SHAddress
				walletMap["p2sh_descriptor"] = multiSigWallet.P2SHDescriptor
				walletMap["address"] = multiSigWallet.P2SHAddress
				walletMap["script_pub_key"] = multiSigWallet.ScriptPubKey
			case "p2wsh":
				walletMap["witness_script"] = multiSigWallet.WitnessScript
				walletMap["p2wsh_address"] = multiSigWallet.P2WSHAddress
				walletMap["p2wsh_descriptor"] = multiSigWallet.P2WSHDescriptor
				walletMap["address"] = multiSigWallet.P2WSHAddress
				// 为 P2WSH 生成正确的 scriptPubKey
				p2wshScriptPubKey, _ := hex.DecodeString("0020" + hex.EncodeToString(witnessScriptHash[:]))
				walletMap["script_pub_key"] = hex.EncodeToString(p2wshScriptPubKey)
			case "p2sh-p2wsh":
				walletMap["redeem_script"] = multiSigWallet.RedeemScript
				walletMap["witness_script"] = multiSigWallet.WitnessScript
				walletMap["p2sh_p2wsh_address"] = multiSigWallet.P2SHP2WSHAddress
				walletMap["p2sh_descriptor"] = multiSigWallet.P2SHDescriptor
				walletMap["p2wsh_descriptor"] = multiSigWallet.P2WSHDescriptor
				walletMap["address"] = multiSigWallet.P2SHP2WSHAddress
				// 为 P2SH-P2WSH 生成正确的 scriptPubKey
				scriptHash := btcutil.Hash160(p2wshScript)
				p2shP2wshScriptPubKey, _ := hex.DecodeString("a914" + hex.EncodeToString(scriptHash) + "87")
				walletMap["script_pub_key"] = hex.EncodeToString(p2shP2wshScriptPubKey)
			}

			// 转换为JSON格式
			jsonData, err := json.MarshalIndent(walletMap, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to format wallet data: %v", err)
			}

			// 处理每个输出目标
			for _, target := range outputTargets {
				if target.Method == "fs" {
					// 文件系统输出
					if err := util.SaveToFileSystem(jsonData, target.Path); err != nil {
						return err
					}
					fmt.Printf("Multisig wallet saved to: %s\n", target.Path)
				} else if target.Method == "googledrive" {
					// Google Drive输出
					fileURL, err := util.UploadToGoogleDrive(jsonData, target.Path)
					if err != nil {
						return fmt.Errorf("failed to upload to Google Drive (%s): %v", target.Path, err)
					}
					fmt.Printf("Multisig wallet saved to Google Drive: %s\n", fileURL)
				} else if target.Method == "dropbox" {
					// Dropbox输出
					fileURL, err := util.UploadToDropbox(jsonData, target.Path)
					if err != nil {
						return fmt.Errorf("failed to upload to Dropbox (%s): %v", target.Path, err)
					}
					fmt.Printf("Multisig wallet saved to Dropbox: %s\n", fileURL)
				} else if target.Method == "onedrive" {
					// OneDrive输出
					fileURL, err := util.UploadToOneDrive(jsonData, target.Path)
					if err != nil {
						return fmt.Errorf("failed to upload to OneDrive (%s): %v", target.Path, err)
					}
					fmt.Printf("Multisig wallet saved to OneDrive: %s\n", fileURL)
				}
			}

			return nil
		},
	}

	// 添加标志
	cmd.Flags().StringVar(&multisigType, "type", "p2sh", "Multisig type (p2sh, p2wsh, p2sh-p2wsh)")
	cmd.Flags().IntVar(&m, "m", 2, "Number of required signatures (m)")
	cmd.Flags().IntVar(&n, "n", 3, "Total number of public keys (n)")
	cmd.Flags().StringVar(&publicKeysStr, "publicKeys", "", "Comma-separated list of public keys (hex encoded)")
	cmd.Flags().StringVar(&outputPaths, "out", "", "Comma-separated output paths for multisig wallet (format: 'method1:path1,method2:path2,...')")
	cmd.Flags().BoolVar(&useTestnet, "testnet", false, "Use testnet instead of mainnet")

	// 标记必需的标志
	cmd.MarkFlagRequired("publicKeys")

	return cmd
}

// 创建多签脚本
func createMultisigScript(m int, pubKeys []*btcec.PublicKey) ([]byte, error) {
	// 从公钥列表创建脚本
	builder := txscript.NewScriptBuilder()

	// OP_m
	builder.AddOp(byte(txscript.OP_1 - 1 + m))

	// 添加所有公钥 (已经按BIP67排序)
	for _, pubKey := range pubKeys {
		builder.AddData(pubKey.SerializeCompressed())
	}

	// OP_n OP_CHECKMULTISIG
	builder.AddOp(byte(txscript.OP_1 - 1 + len(pubKeys)))
	builder.AddOp(txscript.OP_CHECKMULTISIG)

	// 构建脚本
	script, err := builder.Script()
	if err != nil {
		return nil, fmt.Errorf("failed to build script: %v", err)
	}

	return script, nil
}

// 计算描述符校验和
func calculateDescriptorChecksum(desc string) (string, error) {
	// 描述符校验和算法
	// 1. 取 SHA256 哈希
	// 2. 取 SHA256 哈希的前 4 字节
	// 3. 使用 Base58Check 编码
	hash := sha256.Sum256([]byte(desc))
	hash = sha256.Sum256(hash[:])
	checksum := hash[:4]

	// 转换为 base58 编码
	return base58.Encode(checksum), nil
}

// 构建多签描述符
func buildMultisigDescriptor(requiredSigs int, pubKeys []string, isSegWit bool) (string, error) {
	// 排序公钥
	sortedPubKeys := make([]string, len(pubKeys))
	copy(sortedPubKeys, pubKeys)

	// 构建 multi 部分
	multiPart := fmt.Sprintf("multi(%d", requiredSigs)
	for _, pubKey := range sortedPubKeys {
		multiPart += "," + pubKey
	}
	multiPart += ")"

	// 根据类型构建完整描述符
	var descriptor string
	if isSegWit {
		descriptor = "wsh(" + multiPart + ")"
	} else {
		descriptor = "sh(" + multiPart + ")"
	}

	// 计算校验和
	checksum, err := calculateDescriptorChecksum(descriptor)
	if err != nil {
		return "", err
	}

	// 添加校验和
	return descriptor + "#" + checksum, nil
}
