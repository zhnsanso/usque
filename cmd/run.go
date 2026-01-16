package cmd

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Diniboy1123/usque/internal/config"
	"github.com/Diniboy1123/usque/internal/core"
	"github.com/Diniboy1123/usque/internal/inbound/mixed"
	"github.com/Diniboy1123/usque/internal/inbound/tun"
	"github.com/Diniboy1123/usque/internal/router"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run usque with a configuration file",
	Long:  `Starts all services (inbounds, transports, etc.) based on the specified JSON configuration file.`,
	Run: func(cmd *cobra.Command, args []string) {
		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			log.Fatalf("Failed to get config path: %v", err)
		}
		if configPath == "" {
			log.Fatalf("A configuration file must be provided via the --config or -c flag.")
		}
		newConfig, err := config.LoadNewConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load new configuration from %s: %v", configPath, err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// 1. Create Router
		r := router.New()

		var inbounds []core.Inbound

		// 2. Create Inbounds
		for _, inboundOptions := range newConfig.Inbounds {
			var inbound core.Inbound
			var err error
			switch inboundOptions.Type {
			case "tun":
				inbound, err = tun.New(ctx, r, inboundOptions)
			case "mixed":
				inbound, err = mixed.New(ctx, r, inboundOptions)
			default:
				log.Printf("WARN: Unknown inbound type '%s', skipping", inboundOptions.Type)
				continue
			}
			if err != nil {
				log.Fatalf("Failed to create inbound '%s': %v", inboundOptions.Tag, err)
			}
			inbounds = append(inbounds, inbound)
		}

		// 3. Start Inbounds
		for _, inbound := range inbounds {
			if err := inbound.Start(); err != nil {
				log.Fatalf("Failed to start inbound '%s': %v", inbound.Tag(), err)
			}
		}

		log.Printf("Application started successfully. %d inbounds running.", len(inbounds))

		// Wait for shutdown signal
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Shutting down...")
		for _, inbound := range inbounds {
			if err := inbound.Close(); err != nil {
				log.Printf("Error closing inbound '%s': %v", inbound.Tag(), err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
