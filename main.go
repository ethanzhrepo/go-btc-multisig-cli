package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ethanzhrepo/go-btc-multisig-cli/cmd"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	version = "0.0.1"
)

func main() {
	// 设置信号处理，确保在程序中断时恢复终端
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nRestoring terminal...")
		// 强制恢复终端设置
		term.Restore(int(syscall.Stdin), nil)
		os.Exit(1)
	}()

	// 创建根命令
	rootCmd := &cobra.Command{
		Use:     "go-btc-multisig-cli",
		Short:   "Bitcoin multisig wallet CLI tool",
		Version: version,
	}

	// 添加子命令
	rootCmd.AddCommand(cmd.ConfigCmd())
	rootCmd.AddCommand(cmd.GetGasPriceCmd())
	rootCmd.AddCommand(cmd.GenerateWalletCmd())
	rootCmd.AddCommand(cmd.GenerateMultiCmd())
	rootCmd.AddCommand(cmd.GetPublicKeyCmd())
	rootCmd.AddCommand(cmd.TxCmd())
	// rootCmd.AddCommand(cmd.GetBalanceCmd()) // 暂时禁用 balance 功能

	// 执行命令
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		// 确保即使出错也恢复终端设置
		term.Restore(int(syscall.Stdin), nil)
		os.Exit(1)
	}
}
