package util

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox"
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/files"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

// 添加DropboxOAuthConfig结构体
type DropboxOAuthConfig struct {
	AppKey    string `json:"app_key"`
	AppSecret string `json:"app_secret"`
}

// GetDropboxOAuthConfig retrieves OAuth configuration from environment variables or falls back to defaults
func GetDropboxOAuthConfig() (DropboxOAuthConfig, error) {
	// Try to get credentials from environment variables first
	appKey := os.Getenv("DROPBOX_APP_KEY")
	appSecret := os.Getenv("DROPBOX_APP_SECRET")

	// Default configuration (only used if environment variables are not set)
	defaultConfig := DropboxOAuthConfig{
		AppKey:    appKey,
		AppSecret: appSecret,
	}

	// If environment variables are not set, try to load from config file
	if appKey == "" || appSecret == "" {
		// Get user home directory
		usr, err := user.Current()
		if err != nil {
			return defaultConfig, fmt.Errorf("cannot get user home directory: %v", err)
		}

		// Config directory and file path
		configDir := filepath.Join(usr.HomeDir, ".btc-multisig")
		configFile := filepath.Join(configDir, "dropbox.json")

		// Check if config file exists
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			// Create config directory
			if err := os.MkdirAll(configDir, 0700); err != nil {
				return defaultConfig, fmt.Errorf("failed to create config directory: %v", err)
			}

			// Write default config to file
			configData, err := json.MarshalIndent(defaultConfig, "", "  ")
			if err != nil {
				return defaultConfig, fmt.Errorf("failed to marshal config: %v", err)
			}

			if err := os.WriteFile(configFile, configData, 0600); err != nil {
				return defaultConfig, fmt.Errorf("failed to write config file: %v", err)
			}

			fmt.Printf("Created new Dropbox OAuth configuration at %s\n", configFile)
			fmt.Println("Please set DROPBOX_APP_KEY and DROPBOX_APP_SECRET environment variables")
			return defaultConfig, nil
		}

		// Read existing config file
		configData, err := os.ReadFile(configFile)
		if err != nil {
			return defaultConfig, fmt.Errorf("failed to read config file: %v", err)
		}

		// Parse config
		var config DropboxOAuthConfig
		if err := json.Unmarshal(configData, &config); err != nil {
			return defaultConfig, fmt.Errorf("failed to parse config file: %v", err)
		}

		return config, nil
	}

	return defaultConfig, nil
}

// 修改Dropbox OAuth配置中的重定向URI
func UploadToDropbox(data []byte, filePath string) (string, error) {
	ctx := context.Background()

	// 获取OAuth配置
	oauthConfig, err := GetDropboxOAuthConfig()
	if err != nil {
		fmt.Printf("Warning: Using default Dropbox OAuth credentials: %v\n", err)
		// 继续使用默认值
	}

	// 设置OAuth 2.0配置
	redirectURI := "http://localhost:18081/dropbox-callback"
	config := &oauth2.Config{
		ClientID:     oauthConfig.AppKey,
		ClientSecret: oauthConfig.AppSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://www.dropbox.com/oauth2/authorize",
			TokenURL: "https://api.dropboxapi.com/oauth2/token",
		},
		Scopes:      []string{"files.content.write"},
		RedirectURL: redirectURI,
	}

	// 创建一个随机状态字符串
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	// 添加authCode变量声明
	var authCode string

	// 创建独立的路由多路复用器
	mux := http.NewServeMux()

	// 设置服务器使用自定义多路复用器
	server := &http.Server{Addr: ":18081", Handler: mux}

	// 为dropbox使用专用路径
	mux.HandleFunc("/dropbox-callback", func(w http.ResponseWriter, r *http.Request) {
		// 验证状态值
		if r.FormValue("state") != state {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		authCode = r.FormValue("code")
		if authCode == "" {
			http.Error(w, "No code found", http.StatusBadRequest)
			return
		}

		// 响应用户
		fmt.Fprint(w, "<h1>Success!</h1><p>You can now close this window and return to the command line.</p>")

		// 关闭HTTP服务器
		go func() {
			time.Sleep(1 * time.Second)
			server.Shutdown(ctx)
		}()
	})

	// 修改授权URL，不再添加重定向URI参数
	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline)

	// 打开浏览器获取授权
	fmt.Println("Opening browser for Dropbox authentication...")
	if err := browser.OpenURL(authURL); err != nil {
		return "", fmt.Errorf("failed to open browser: %v, please visit this URL manually: %s", err, authURL)
	}

	// 等待接收重定向
	fmt.Println("Waiting for authentication...")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return "", fmt.Errorf("HTTP server error: %v", err)
	}

	if authCode == "" {
		return "", fmt.Errorf("failed to get authorization code")
	}

	// 交换授权码获取token
	token, err := config.Exchange(ctx, authCode)
	if err != nil {
		return "", fmt.Errorf("failed to exchange token: %v", err)
	}

	// 创建Dropbox客户端
	config1 := dropbox.Config{
		Token:    token.AccessToken,
		LogLevel: dropbox.LogOff,
	}
	client := files.New(config1)

	// 确保文件路径以/开头
	if !strings.HasPrefix(filePath, "/") {
		filePath = "/" + filePath
	}

	// 检查文件是否已存在
	_, err = client.GetMetadata(&files.GetMetadataArg{Path: filePath})
	if err == nil {
		return "", fmt.Errorf("file already exists in Dropbox: %s (use a different path to avoid overwriting)", filePath)
	}

	// 上传文件
	commitInfo := files.CommitInfo{
		Path: filePath,
		Mode: &files.WriteMode{
			Tagged: dropbox.Tagged{
				Tag: "add",
			},
		},
	}
	uploadArg := &files.UploadArg{
		CommitInfo: commitInfo,
	}
	uploadResult, err := client.Upload(uploadArg, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to upload to Dropbox: %v", err)
	}

	// 去掉创建共享链接的部分
	return fmt.Sprintf("File uploaded successfully to Dropbox: %s (private)", uploadResult.PathDisplay), nil
}

// 从Dropbox下载文件
func DownloadFromDropbox(filePath string) ([]byte, error) {
	ctx := context.Background()

	// 获取OAuth配置
	oauthConfig, err := GetDropboxOAuthConfig()
	if err != nil {
		fmt.Printf("Warning: Using default Dropbox OAuth credentials: %v\n", err)
		// 继续使用默认值
	}

	// 设置OAuth 2.0配置
	redirectURI := "http://localhost:18081/dropbox-callback"
	config := &oauth2.Config{
		ClientID:     oauthConfig.AppKey,
		ClientSecret: oauthConfig.AppSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://www.dropbox.com/oauth2/authorize",
			TokenURL: "https://api.dropboxapi.com/oauth2/token",
		},
		Scopes:      []string{"files.content.read"},
		RedirectURL: redirectURI,
	}

	// 创建一个随机状态字符串
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	// 添加authCode变量声明
	var authCode string

	// 创建独立的路由多路复用器
	mux := http.NewServeMux()

	// 设置服务器使用自定义多路复用器
	server := &http.Server{Addr: ":18081", Handler: mux}

	// 为dropbox使用专用路径
	mux.HandleFunc("/dropbox-callback", func(w http.ResponseWriter, r *http.Request) {
		// 验证状态值
		if r.FormValue("state") != state {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		authCode = r.FormValue("code")
		if authCode == "" {
			http.Error(w, "No code found", http.StatusBadRequest)
			return
		}

		// 响应用户
		fmt.Fprint(w, "<h1>Success!</h1><p>You can now close this window and return to the command line.</p>")

		// 关闭HTTP服务器
		go func() {
			time.Sleep(1 * time.Second)
			server.Shutdown(ctx)
		}()
	})

	// 授权URL
	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline)

	// 打开浏览器获取授权
	fmt.Println("Opening browser for Dropbox authentication...")
	if err := browser.OpenURL(authURL); err != nil {
		return nil, fmt.Errorf("failed to open browser: %v, please visit this URL manually: %s", err, authURL)
	}

	// 等待接收重定向
	fmt.Println("Waiting for authentication...")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return nil, fmt.Errorf("HTTP server error: %v", err)
	}

	if authCode == "" {
		return nil, fmt.Errorf("failed to get authorization code")
	}

	// 交换授权码获取token
	token, err := config.Exchange(ctx, authCode)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %v", err)
	}

	// 创建Dropbox客户端
	config1 := dropbox.Config{
		Token:    token.AccessToken,
		LogLevel: dropbox.LogOff,
	}
	client := files.New(config1)

	// 确保文件路径以/开头
	if !strings.HasPrefix(filePath, "/") {
		filePath = "/" + filePath
	}

	// 检查文件是否存在
	metadata, err := client.GetMetadata(&files.GetMetadataArg{Path: filePath})
	if err != nil {
		return nil, fmt.Errorf("file not found in Dropbox: %s - %v", filePath, err)
	}

	// 检查元数据类型确保是文件而不是文件夹
	fileMetadata, ok := metadata.(*files.FileMetadata)
	if !ok {
		return nil, fmt.Errorf("path refers to a folder, not a file: %s", filePath)
	}

	// 下载文件
	downloadArg := &files.DownloadArg{
		Path: filePath,
	}

	_, reader, err := client.Download(downloadArg)
	if err != nil {
		return nil, fmt.Errorf("failed to download file from Dropbox: %v", err)
	}
	defer reader.Close()

	// 读取文件内容
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read file content: %v", err)
	}

	fmt.Printf("Successfully downloaded file from Dropbox: %s (%d bytes)\n",
		fileMetadata.Name, len(data))
	return data, nil
}
