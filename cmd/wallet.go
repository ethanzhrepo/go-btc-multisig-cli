package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"syscall"
	"unicode"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/ethanzhrepo/go-btc-multisig-cli/util"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

// 输出目标结构
type OutputTarget struct {
	Method string // "fs" 或 "googledrive" 或 "dropbox"
	Path   string // 文件路径
}

// 验证密码复杂度
func validatePasswordComplexity(password string) error {
	if len(password) < 10 {
		return fmt.Errorf("password must be at least 10 characters long")
	}

	// 检查是否包含大写字母
	hasUpper := false
	// 检查是否包含小写字母
	hasLower := false
	// 检查是否包含数字
	hasDigit := false
	// 检查是否包含特殊字符
	hasSpecial := false

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// 修改现有的readPasswordFromConsole函数
func readPasswordFromConsole() (string, error) {
	fmt.Print("Enter password to encrypt mnemonic (input will be hidden): ")

	// 读取密码，不回显
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // 换行

	if err != nil {
		return "", fmt.Errorf("failed to read password: %v", err)
	}

	password := string(passwordBytes)
	if len(password) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}

	// 验证密码复杂度
	if err := validatePasswordComplexity(password); err != nil {
		return "", err
	}

	// 确认密码
	fmt.Print("Confirm password (input will be hidden): ")
	confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // 换行

	if err != nil {
		return "", fmt.Errorf("failed to read password confirmation: %v", err)
	}

	if string(confirmBytes) != password {
		return "", fmt.Errorf("passwords do not match")
	}

	return password, nil
}

// GenerateWalletCmd 返回 generateWallet 命令
func GenerateWalletCmd() *cobra.Command {
	var showMnemonic bool
	var useTestnet bool
	var outputStr string

	cmd := &cobra.Command{
		Use:   "generateWallet",
		Short: "Generate a new wallet with different address types",
		Long:  "Generate a new wallet with P2PKH, P2SH, P2WPKH, P2WSH and P2TR addresses",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 解析输出目标
			outputTargets, err := parseOutputTargets(outputStr)
			if err != nil {
				return err
			}

			// 生成助记词和种子
			entropy, err := bip39.NewEntropy(256)
			if err != nil {
				return fmt.Errorf("failed to generate entropy: %v", err)
			}

			mnemonic, err := bip39.NewMnemonic(entropy)
			if err != nil {
				return fmt.Errorf("failed to generate mnemonic: %v", err)
			}

			// 显示原始助记词（如果showMnemonic为true）
			if showMnemonic {
				fmt.Println("Mnemonic (24 words):")
				fmt.Println("---------------------------------")
				fmt.Println(mnemonic)
				fmt.Println("---------------------------------")
				fmt.Println("IMPORTANT: Write these words down on paper and keep them safe!")
			}

			// 从助记词生成种子
			seed := bip39.NewSeed(mnemonic, "")

			// 如果指定了输出目标，需要加密助记词
			var password string
			var jsonData []byte

			if len(outputTargets) > 0 {
				// 从控制台读取密码
				password, err = readPasswordFromConsole()
				if err != nil {
					return err
				}

				// 使用密码加密助记词
				encryptedData, err := encryptMnemonic(mnemonic, password)
				if err != nil {
					return fmt.Errorf("failed to encrypt mnemonic: %v", err)
				}

				// 转换为JSON格式
				jsonData, err = json.MarshalIndent(encryptedData, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to format encrypted data: %v", err)
				}

				// 处理每个输出目标
				for _, target := range outputTargets {
					if target.Method == "fs" {
						// 文件系统输出
						if err := util.SaveToFileSystem(jsonData, target.Path); err != nil {
							return err
						}
					} else if target.Method == "googledrive" {
						// Google Drive输出
						fileURL, err := util.UploadToGoogleDrive(jsonData, target.Path)
						if err != nil {
							return fmt.Errorf("failed to upload to Google Drive (%s): %v", target.Path, err)
						}
						fmt.Printf("Encrypted mnemonic saved to Google Drive: %s\n", fileURL)
					} else if target.Method == "dropbox" {
						// Dropbox输出
						fileURL, err := util.UploadToDropbox(jsonData, target.Path)
						if err != nil {
							return fmt.Errorf("failed to upload to Dropbox (%s): %v", target.Path, err)
						}
						fmt.Printf("Encrypted mnemonic saved to Dropbox: %s\n", fileURL)
					} else if target.Method == "onedrive" {
						// OneDrive输出
						fileURL, err := util.UploadToOneDrive(jsonData, target.Path)
						if err != nil {
							return fmt.Errorf("failed to upload to OneDrive (%s): %v", target.Path, err)
						}
						fmt.Printf("Encrypted mnemonic saved to OneDrive: %s\n", fileURL)
					}
				}

			}

			// 根据参数选择网络
			var params *chaincfg.Params
			var networkName string
			var coinType uint32

			if useTestnet {
				params = &chaincfg.TestNet3Params
				networkName = "Testnet"
				coinType = 1 // testnet
			} else {
				params = &chaincfg.MainNetParams
				networkName = "Mainnet"
				coinType = 0 // mainnet
			}

			// 3. 创建主私钥 (BIP32)
			masterKey, err := hdkeychain.NewMaster(seed, params)
			if err != nil {
				return fmt.Errorf("failed to generate master key: %v", err)
			}

			// 4. 推导出BIP44路径私钥
			// m/44'/0'/0'/0/0 (主网) 或 m/44'/1'/0'/0/0 (测试网)
			purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 44)
			if err != nil {
				return fmt.Errorf("failed to derive purpose: %v", err)
			}

			coinTypeKey, err := purpose.Derive(hdkeychain.HardenedKeyStart + coinType)
			if err != nil {
				return fmt.Errorf("failed to derive coin type: %v", err)
			}

			account, err := coinTypeKey.Derive(hdkeychain.HardenedKeyStart + 0)
			if err != nil {
				return fmt.Errorf("failed to derive account: %v", err)
			}

			change, err := account.Derive(0)
			if err != nil {
				return fmt.Errorf("failed to derive change: %v", err)
			}

			addressKey, err := change.Derive(0)
			if err != nil {
				return fmt.Errorf("failed to derive address: %v", err)
			}

			// 5. 从扩展密钥获取私钥和公钥
			privateKey, err := addressKey.ECPrivKey()
			if err != nil {
				return fmt.Errorf("failed to get private key: %v", err)
			}

			publicKey := privateKey.PubKey()

			// 6. 生成各种类型的地址
			// 显示钱包信息
			fmt.Printf("Generated Wallet Addresses (%s):\n", networkName)
			fmt.Println("========================================")

			// P2PKH (传统地址)
			p2pkhAddr, err := generateP2PKHAddress(publicKey, params)
			if err != nil {
				return fmt.Errorf("failed to generate P2PKH address: %v", err)
			}
			fmt.Printf("P2PKH address: %s\n", p2pkhAddr)

			// P2WPKH (原生隔离见证)
			p2wpkhAddr, err := generateP2WPKHAddress(publicKey, params)
			if err != nil {
				return fmt.Errorf("failed to generate P2WPKH address: %v", err)
			}
			fmt.Printf("P2WPKH address: %s\n", p2wpkhAddr)

			// P2SH (脚本哈希)
			p2shAddr, err := generateP2SHAddress(publicKey, params)
			if err != nil {
				return fmt.Errorf("failed to generate P2SH address: %v", err)
			}
			fmt.Printf("P2SH address: %s\n", p2shAddr)

			// P2WSH (隔离见证脚本哈希)
			p2wshAddr, err := generateP2WSHAddress(publicKey, params)
			if err != nil {
				return fmt.Errorf("failed to generate P2WSH address: %v", err)
			}
			fmt.Printf("P2WSH address: %s\n", p2wshAddr)

			// P2TR (Taproot)
			p2trAddr, err := generateP2TRAddress(publicKey, params)
			if err != nil {
				return fmt.Errorf("failed to generate P2TR address: %v", err)
			}
			fmt.Printf("P2TR address: %s\n", p2trAddr)

			return nil
		},
	}

	// 添加标志
	cmd.Flags().BoolVarP(&showMnemonic, "show", "s", false, "Show mnemonic phrase")
	cmd.Flags().BoolVarP(&useTestnet, "testnet", "t", false, "Use testnet instead of mainnet")

	// 修改输出标志
	cmd.Flags().StringVarP(&outputStr, "out", "o", "", "Output targets (comma separated list in format 'method:path', e.g. 'fs:/tmp/key.json,googledrive:/backup/key.json,dropbox:/backup/key.json')")

	return cmd
}

// 修改加密函数使用 Argon2id
func encryptMnemonic(mnemonic, password string) (util.EncryptedMnemonic, error) {
	// 初始化返回结构
	result := util.EncryptedMnemonic{
		Version:       1,
		Algorithm:     "AES-256-GCM",
		KeyDerivation: "Argon2id",
		Memory:        1024 * 1024,
		Iterations:    12,
		Parallelism:   4,
		KeyLength:     32,
	}

	// 生成随机salt (16字节)
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return result, fmt.Errorf("failed to generate random salt: %v", err)
	}
	result.Salt = base64.StdEncoding.EncodeToString(salt)

	// 使用 Argon2id 从密码派生密钥
	key := argon2.IDKey(
		[]byte(password),
		salt,
		result.Iterations,
		result.Memory,
		result.Parallelism,
		result.KeyLength,
	)

	// 创建cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return result, err
	}

	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return result, err
	}

	// 创建随机nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return result, err
	}
	result.Nonce = base64.StdEncoding.EncodeToString(nonce)

	// 加密数据
	ciphertext := gcm.Seal(nil, nonce, []byte(mnemonic), nil)
	result.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)

	return result, nil
}

// 修改解密函数使用 Argon2id
// func decryptMnemonic(encryptedData EncryptedMnemonic, password string) (string, error) {
// 	// 解码Base64数据
// 	salt, err := base64.StdEncoding.DecodeString(encryptedData.Salt)
// 	if err != nil {
// 		return "", fmt.Errorf("invalid salt format: %v", err)
// 	}

// 	nonce, err := base64.StdEncoding.DecodeString(encryptedData.Nonce)
// 	if err != nil {
// 		return "", fmt.Errorf("invalid nonce format: %v", err)
// 	}

// 	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData.Ciphertext)
// 	if err != nil {
// 		return "", fmt.Errorf("invalid ciphertext format: %v", err)
// 	}

// 	// 使用 Argon2id 派生密钥
// 	var key []byte
// 	if encryptedData.KeyDerivation == "Argon2id" {
// 		// 使用存储的 Argon2id 参数
// 		key = argon2.IDKey(
// 			[]byte(password),
// 			salt,
// 			encryptedData.Iterations,
// 			encryptedData.Memory,
// 			encryptedData.Parallelism,
// 			encryptedData.KeyLength,
// 		)
// 	} else {
// 		// 向后兼容 PBKDF2
// 		key = pbkdf2.Key([]byte(password), salt, 4096, 32, sha256.New)
// 	}

// 	// 创建cipher
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return "", err
// 	}

// 	// 创建GCM模式
// 	gcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		return "", err
// 	}

// 	// 解密
// 	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
// 	if err != nil {
// 		return "", fmt.Errorf("decryption failed, incorrect password: %v", err)
// 	}

// 	return string(plaintext), nil
// }

// 生成P2PKH地址 (Pay to Public Key Hash)
func generateP2PKHAddress(publicKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	pubKeyHash := btcutil.Hash160(publicKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// 生成P2WPKH地址 (Pay to Witness Public Key Hash)
func generateP2WPKHAddress(publicKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	pubKeyHash := btcutil.Hash160(publicKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// 生成P2SH地址 (Pay to Script Hash)
func generateP2SHAddress(publicKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	// 创建P2WPKH脚本
	pubKeyHash := btcutil.Hash160(publicKey.SerializeCompressed())
	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(pubKeyHash).
		Script()
	if err != nil {
		return "", err
	}

	// 将P2WPKH脚本放入P2SH中 (P2SH-P2WPKH)
	scriptHash := btcutil.Hash160(script)
	addr, err := btcutil.NewAddressScriptHash(scriptHash, params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// 生成P2WSH地址 (Pay to Witness Script Hash)
func generateP2WSHAddress(publicKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	// 创建一个简单的多签脚本 (1-of-1 multisig)
	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(publicKey.SerializeCompressed()).
		AddOp(txscript.OP_1).
		AddOp(txscript.OP_CHECKMULTISIG).
		Script()
	if err != nil {
		return "", err
	}

	// 计算脚本哈希
	scriptHash := sha256.Sum256(script)
	addr, err := btcutil.NewAddressWitnessScriptHash(scriptHash[:], params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// 生成P2TR地址 (Pay to Taproot)
func generateP2TRAddress(publicKey *btcec.PublicKey, params *chaincfg.Params) (string, error) {
	// 注意：在真实场景中，你可能需要考虑更多关于Taproot的细节
	// 这里我们使用一个简化的版本
	internalKey := publicKey

	// 创建Taproot输出密钥
	taprootKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	addr, err := btcutil.NewAddressTaproot(taprootKey.SerializeCompressed()[1:], params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// 解析输出字符串
func parseOutputTargets(outputStr string) ([]OutputTarget, error) {
	if outputStr == "" {
		return nil, nil
	}

	var targets []OutputTarget
	outputs := strings.Split(outputStr, ",")

	for _, out := range outputs {
		parts := strings.SplitN(out, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid output format '%s', expected 'method:path'", out)
		}

		method := strings.TrimSpace(parts[0])
		path := strings.TrimSpace(parts[1])

		// 添加onedrive支持
		if method != "fs" && method != "googledrive" && method != "dropbox" && method != "onedrive" {
			return nil, fmt.Errorf("unsupported output method '%s', supported methods: fs, googledrive, dropbox, onedrive", method)
		}

		if path == "" {
			return nil, fmt.Errorf("empty path specified for method '%s'", method)
		}

		targets = append(targets, OutputTarget{Method: method, Path: path})
	}

	return targets, nil
}
