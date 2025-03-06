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
)

// 添加OneDriveOAuthConfig结构体
type OneDriveOAuthConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// GetOneDriveOAuthConfig retrieves OAuth configuration from environment variables or falls back to defaults
func GetOneDriveOAuthConfig() (OneDriveOAuthConfig, error) {
	// Try to get credentials from environment variables first
	clientID := os.Getenv("ONEDRIVE_CLIENT_ID")
	clientSecret := os.Getenv("ONEDRIVE_CLIENT_SECRET")

	// Default configuration (only used if environment variables are not set)
	defaultConfig := OneDriveOAuthConfig{
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
		configFile := filepath.Join(configDir, "onedrive.json")

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

			fmt.Printf("Created new OneDrive OAuth configuration at %s\n", configFile)
			fmt.Println("Please set ONEDRIVE_CLIENT_ID and ONEDRIVE_CLIENT_SECRET environment variables")
			return defaultConfig, nil
		}

		// Read existing config file
		configData, err := os.ReadFile(configFile)
		if err != nil {
			return defaultConfig, fmt.Errorf("failed to read config file: %v", err)
		}

		// Parse config
		var config OneDriveOAuthConfig
		if err := json.Unmarshal(configData, &config); err != nil {
			return defaultConfig, fmt.Errorf("failed to parse config file: %v", err)
		}

		return config, nil
	}

	return defaultConfig, nil
}

// 上传到OneDrive
func UploadToOneDrive(data []byte, filePath string) (string, error) {
	ctx := context.Background()

	// 获取OAuth配置
	oauthConfig, err := GetOneDriveOAuthConfig()
	if err != nil {
		fmt.Printf("Warning: Using default OneDrive OAuth credentials: %v\n", err)
		// 继续使用默认值
	}

	// 设置OAuth 2.0配置
	redirectURI := "http://localhost:18082/onedrive"
	config := &oauth2.Config{
		ClientID:     oauthConfig.ClientID,
		ClientSecret: oauthConfig.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		},
		Scopes:      []string{"Files.ReadWrite"},
		RedirectURL: redirectURI,
	}

	// 创建一个随机状态字符串
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	// 声明authCode变量
	var authCode string

	// 创建独立的路由多路复用器
	mux := http.NewServeMux()

	// 设置服务器使用自定义多路复用器
	server := &http.Server{Addr: ":18082", Handler: mux}

	// 为OneDrive使用专用路径
	mux.HandleFunc("/onedrive", func(w http.ResponseWriter, r *http.Request) {
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

	// 获取授权URL
	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline)

	// 打开浏览器获取授权
	fmt.Println("Opening browser for OneDrive authentication...")
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

	// 创建HTTP客户端
	client := config.Client(ctx, token)

	// 处理文件路径
	dirPath := filepath.Dir(filePath)
	fileName := filepath.Base(filePath)

	// 检查文件是否存在并上传
	if dirPath == "/" || dirPath == "." {
		// 上传到根目录
		return uploadFileToOneDriveRoot(client, data, fileName)
	} else {
		// 上传到指定目录，需要先创建或查找目录
		return uploadFileToOneDriveFolder(client, data, dirPath, fileName)
	}
}

// 上传文件到OneDrive根目录
func uploadFileToOneDriveRoot(client *http.Client, data []byte, fileName string) (string, error) {
	// 检查文件是否已存在
	checkURL := "https://graph.microsoft.com/v1.0/me/drive/root:/" + fileName
	req, err := http.NewRequest("GET", checkURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		// 可能网络错误，继续尝试上传
	} else if resp.StatusCode == 200 {
		return "", fmt.Errorf("file already exists in OneDrive: %s (use a different path to avoid overwriting)", fileName)
	}

	// 上传文件
	uploadURL := "https://graph.microsoft.com/v1.0/me/drive/root:/" + fileName + ":/content"
	req, err = http.NewRequest("PUT", uploadURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create upload request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to upload file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	// 获取文件共享链接
	webUrl, ok := result["webUrl"].(string)
	if !ok {
		return "File uploaded successfully to OneDrive root directory", nil
	}

	return webUrl, nil
}

// 上传文件到OneDrive指定文件夹
func uploadFileToOneDriveFolder(client *http.Client, data []byte, folderPath, fileName string) (string, error) {
	// 首先需要检查/创建文件夹结构
	// 由于这需要多个API调用和较复杂的逻辑，这里实现一个简化版本

	// 清理路径并分割成部分
	folderPath = strings.Trim(folderPath, "/")
	pathParts := strings.Split(folderPath, "/")

	// 递归创建或获取文件夹
	folderID, err := ensureOneDriveFolderExists(client, "", pathParts)
	if err != nil {
		return "", fmt.Errorf("failed to create folder structure: %v", err)
	}

	// 在目标文件夹中检查文件是否存在
	checkURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/me/drive/items/%s:/%s", folderID, fileName)
	req, err := http.NewRequest("GET", checkURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		return "", fmt.Errorf("file already exists in OneDrive: %s/%s (use a different path to avoid overwriting)", folderPath, fileName)
	}

	// 上传文件到指定文件夹
	uploadURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/me/drive/items/%s:/%s:/content", folderID, fileName)
	req, err = http.NewRequest("PUT", uploadURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create upload request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to upload file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	webUrl, ok := result["webUrl"].(string)
	if !ok {
		return fmt.Sprintf("File uploaded successfully to OneDrive folder: %s", folderPath), nil
	}

	return webUrl, nil
}

// 递归确保OneDrive文件夹结构存在
func ensureOneDriveFolderExists(client *http.Client, parentID string, pathParts []string) (string, error) {
	if len(pathParts) == 0 {
		return parentID, nil
	}

	currentFolder := pathParts[0]

	// 构建API URL
	var searchURL string
	if parentID == "" {
		// 在根目录搜索
		searchURL = "https://graph.microsoft.com/v1.0/me/drive/root/children?$filter=name eq '" + currentFolder + "' and folder ne null"
	} else {
		// 在特定文件夹搜索
		searchURL = "https://graph.microsoft.com/v1.0/me/drive/items/" + parentID + "/children?$filter=name eq '" + currentFolder + "' and folder ne null"
	}

	// 搜索文件夹
	req, err := http.NewRequest("GET", searchURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	// 检查文件夹是否存在
	var folderID string
	if len(result.Value) > 0 {
		// 文件夹已存在
		folderID = result.Value[0].ID
	} else {
		// 需要创建文件夹
		createURL := "https://graph.microsoft.com/v1.0/me/drive/"
		if parentID == "" {
			createURL += "root/children"
		} else {
			createURL += "items/" + parentID + "/children"
		}

		folderData := map[string]interface{}{
			"name":                              currentFolder,
			"folder":                            map[string]interface{}{},
			"@microsoft.graph.conflictBehavior": "fail",
		}

		jsonData, err := json.Marshal(folderData)
		if err != nil {
			return "", err
		}

		req, err = http.NewRequest("POST", createURL, bytes.NewReader(jsonData))
		if err != nil {
			return "", err
		}
		req.Header.Add("Content-Type", "application/json")

		resp, err = client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("folder creation failed with status %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var newFolder struct {
			ID string `json:"id"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&newFolder); err != nil {
			return "", err
		}

		folderID = newFolder.ID
	}

	// 继续处理路径的下一部分
	return ensureOneDriveFolderExists(client, folderID, pathParts[1:])
}

// 从OneDrive下载文件
func DownloadFromOneDrive(filePath string) ([]byte, error) {
	ctx := context.Background()

	// 获取OAuth配置
	oauthConfig, err := GetOneDriveOAuthConfig()
	if err != nil {
		fmt.Printf("Warning: Using default OneDrive OAuth credentials: %v\n", err)
		// 继续使用默认值
	}

	// 设置OAuth 2.0配置
	redirectURI := "http://localhost:18082/onedrive"
	config := &oauth2.Config{
		ClientID:     oauthConfig.ClientID,
		ClientSecret: oauthConfig.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		},
		Scopes:      []string{"Files.Read"},
		RedirectURL: redirectURI,
	}

	// 创建一个随机状态字符串
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	// 声明authCode变量
	var authCode string

	// 创建独立的路由多路复用器
	mux := http.NewServeMux()

	// 设置服务器使用自定义多路复用器
	server := &http.Server{Addr: ":18082", Handler: mux}

	// 为OneDrive使用专用路径
	mux.HandleFunc("/onedrive", func(w http.ResponseWriter, r *http.Request) {
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

	// 获取授权URL
	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline)

	// 打开浏览器获取授权
	fmt.Println("Opening browser for OneDrive authentication...")
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

	// 创建HTTP客户端
	client := config.Client(ctx, token)

	// 确保文件路径格式正确
	filePath = strings.TrimPrefix(filePath, "/")

	// 构建下载URL - 两种方式：通过路径或ID
	var downloadURL string
	if strings.Contains(filePath, "/") {
		// 假设是路径
		downloadURL = fmt.Sprintf("https://graph.microsoft.com/v1.0/me/drive/root:/%s:/content", filePath)
	} else {
		// 假设是文件ID
		downloadURL = fmt.Sprintf("https://graph.microsoft.com/v1.0/me/drive/items/%s/content", filePath)
	}

	// 发送下载请求
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// 读取文件内容
	fileData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read file content: %v", err)
	}

	fmt.Printf("Successfully downloaded file from OneDrive: %s (%d bytes)\n",
		filePath, len(fileData))
	return fileData, nil
}
