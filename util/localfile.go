package util

import (
	"fmt"
	"os"
	"path/filepath"
)

// SaveToFileSystem 将数据保存到本地文件系统
func SaveToFileSystem(data []byte, path string) error {
	// 创建必要的目录
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("无法创建目录 %s: %v", dir, err)
	}

	// 写入文件
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("无法写入文件 %s: %v", path, err)
	}

	return nil
}

// LoadFromFileSystem 从本地文件系统加载数据
func LoadFromFileSystem(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("无法读取文件 %s: %v", path, err)
	}
	return data, nil
}

// 从本地文件系统下载文件
func DownloadFromFileSystem(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("无法读取文件 %s: %v", path, err)
	}
	return data, nil
}
