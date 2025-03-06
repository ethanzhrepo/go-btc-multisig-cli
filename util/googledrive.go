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

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

// 添加GoogleOAuthConfig结构体
type GoogleOAuthConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// GetGoogleOAuthConfig retrieves OAuth configuration from environment variables or falls back to defaults
func GetGoogleOAuthConfig() (GoogleOAuthConfig, error) {
	// Try to get credentials from environment variables first
	clientID := os.Getenv("GOOGLE_OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET")

	// Default configuration (only used if environment variables are not set)
	defaultConfig := GoogleOAuthConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}

	// If environment variables are not set, try to load from config file
	if clientID == "" || clientSecret == "" {
		// Get user home directory
		usr, err := user.Current()
		if err != nil {
			return defaultConfig, fmt.Errorf("cannot get user home directory: %v", err)
		}

		// Config directory and file path
		configDir := filepath.Join(usr.HomeDir, ".btc-multisig")
		configFile := filepath.Join(configDir, "google.json")

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

			fmt.Printf("Created new OAuth configuration at %s\n", configFile)
			fmt.Println("Please set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET environment variables")
			return defaultConfig, nil
		}

		// Read existing config file
		configData, err := os.ReadFile(configFile)
		if err != nil {
			return defaultConfig, fmt.Errorf("failed to read config file: %v", err)
		}

		// Parse config
		var config GoogleOAuthConfig
		if err := json.Unmarshal(configData, &config); err != nil {
			return defaultConfig, fmt.Errorf("failed to parse config file: %v", err)
		}

		return config, nil
	}

	return defaultConfig, nil
}

// 在Google Drive中检查文件是否存在
func CheckFileExistsInGoogleDrive(srv *drive.Service, fileName string, parentID string) (bool, error) {
	query := fmt.Sprintf("name='%s' and trashed=false", fileName)
	if parentID != "" {
		query += fmt.Sprintf(" and '%s' in parents", parentID)
	}

	fileList, err := srv.Files.List().Q(query).Fields("files(id)").Do()
	if err != nil {
		return false, fmt.Errorf("failed to check if file exists: %v", err)
	}

	return len(fileList.Files) > 0, nil
}

// 修改uploadToGoogleDrive函数以检查文件是否存在
func UploadToGoogleDrive(data []byte, filePath string) (string, error) {
	ctx := context.Background()

	// 获取OAuth配置
	oauthConfig, err := GetGoogleOAuthConfig()
	if err != nil {
		fmt.Printf("Warning: Using default OAuth credentials: %v\n", err)
		// 继续使用默认值
	}

	// 设置OAuth 2.0配置
	config := &oauth2.Config{
		ClientID:     oauthConfig.ClientID,
		ClientSecret: oauthConfig.ClientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{drive.DriveFileScope},
		RedirectURL:  "http://localhost:18080",
	}

	// 创建一个随机状态字符串
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	// 获取授权URL
	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)

	// 启动本地HTTP服务器接收重定向
	var authCode string

	server := &http.Server{Addr: ":18080"}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

	// 打开浏览器获取授权
	fmt.Println("Opening browser for Google authentication...")
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

	// 创建Drive客户端
	client := config.Client(ctx, token)
	srv, err := drive.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return "", fmt.Errorf("failed to create Drive client: %v", err)
	}

	// 准备文件元数据
	fileName := filepath.Base(filePath)
	dirPath := filepath.Dir(filePath)

	// 确保目录存在
	var parentID string
	if dirPath != "/" && dirPath != "." {
		parentID, err = CreateOrGetFolder(srv, dirPath)
		if err != nil {
			return "", fmt.Errorf("failed to create folders: %v", err)
		}
	}

	// 检查文件是否已存在
	exists, err := CheckFileExistsInGoogleDrive(srv, fileName, parentID)
	if err != nil {
		return "", err
	}
	if exists {
		return "", fmt.Errorf("file already exists in Google Drive: %s (use a different path to avoid overwriting)", filePath)
	}

	// 创建文件
	f := &drive.File{
		Name:     fileName,
		MimeType: "application/json",
	}

	if parentID != "" {
		f.Parents = []string{parentID}
	}

	reader := bytes.NewReader(data)
	file, err := srv.Files.Create(f).Media(reader).Do()
	if err != nil {
		return "", fmt.Errorf("failed to create file in Google Drive: %v", err)
	}

	// 清理凭据
	fmt.Println("Cleaning up authentication tokens...")
	// 实际上这里不存储任何token，所以不需要额外清理

	return file.WebViewLink, nil
}

// 在Google Drive中创建或获取文件夹
func CreateOrGetFolder(srv *drive.Service, folderPath string) (string, error) {
	// 分割路径
	parts := strings.Split(strings.Trim(folderPath, "/"), "/")
	var parentID string // 根目录

	// 逐级创建文件夹
	for _, part := range parts {
		// 查找是否已存在此文件夹
		query := fmt.Sprintf("name='%s' and mimeType='application/vnd.google-apps.folder' and trashed=false", part)
		if parentID != "" {
			query += fmt.Sprintf(" and '%s' in parents", parentID)
		}

		fileList, err := srv.Files.List().Q(query).Fields("files(id)").Do()
		if err != nil {
			return "", fmt.Errorf("failed to query folder: %v", err)
		}

		// 如果找到了文件夹，使用它的ID
		if len(fileList.Files) > 0 {
			parentID = fileList.Files[0].Id
			continue
		}

		// 没找到，创建新文件夹
		folder := &drive.File{
			Name:     part,
			MimeType: "application/vnd.google-apps.folder",
		}
		if parentID != "" {
			folder.Parents = []string{parentID}
		}

		newFolder, err := srv.Files.Create(folder).Fields("id").Do()
		if err != nil {
			return "", fmt.Errorf("failed to create folder: %v", err)
		}
		parentID = newFolder.Id
	}

	return parentID, nil
}

// 从Google Drive下载文件
func DownloadFromGoogleDrive(fileName string) ([]byte, error) {
	ctx := context.Background()

	// 获取OAuth配置
	oauthConfig, err := GetGoogleOAuthConfig()
	if err != nil {
		fmt.Printf("Warning: Using default OAuth credentials: %v\n", err)
		// 继续使用默认值
	}

	// 设置OAuth 2.0配置
	config := &oauth2.Config{
		ClientID:     oauthConfig.ClientID,
		ClientSecret: oauthConfig.ClientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{drive.DriveFileScope},
		RedirectURL:  "http://localhost:18080",
	}

	// 创建随机状态字符串
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	// 获取授权URL
	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)

	// 启动本地HTTP服务器接收重定向
	var authCode string

	server := &http.Server{Addr: ":18080"}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

	// 打开浏览器获取授权
	fmt.Println("Opening browser for Google authentication...")
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

	// 创建Drive客户端
	client := config.Client(ctx, token)
	srv, err := drive.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create Drive client: %v", err)
	}

	//
	// 从文件路径获取fileId
	fileId := ""
	pathParts := strings.Split(strings.Trim(fileName, "/"), "/")
	parentId := "root" // 从根目录开始

	// 逐级查找目录和文件
	for i, part := range pathParts {
		isLast := i == len(pathParts)-1
		query := fmt.Sprintf("name='%s' and '%s' in parents and trashed=false", part, parentId)

		list, err := srv.Files.List().Q(query).Fields("files(id)").Do()
		if err != nil {
			return nil, fmt.Errorf("查找路径%s失败: %v", strings.Join(pathParts[:i+1], "/"), err)
		}

		if len(list.Files) == 0 {
			return nil, fmt.Errorf("路径%s不存在", strings.Join(pathParts[:i+1], "/"))
		}

		if isLast {
			fileId = list.Files[0].Id
		} else {
			parentId = list.Files[0].Id
		}
	}

	// 检查文件是否存在
	file, err := srv.Files.Get(fileId).Fields("id, name").Do()
	if err != nil {
		return nil, fmt.Errorf("文件%s不存在或无法访问: %v", fileName, err)
	}

	// 下载文件内容
	resp, err := srv.Files.Get(fileId).Download()
	if err != nil {
		return nil, fmt.Errorf("下载文件%s失败: %v", fileName, err)
	}
	defer resp.Body.Close()

	// 读取文件内容
	fileData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取文件%s内容失败: %v", fileName, err)
	}

	fmt.Printf("成功从Google Drive下载文件: %s\n", file.Name)
	return fileData, nil
}
