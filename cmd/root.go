package cmd

import (
	"log"

	"github.com/Diniboy1123/usque/config"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "usque",
	Short: "Usque Warp CLI",
	Long:  "An unofficial Cloudflare Warp CLI that uses the MASQUE protocol and exposes the tunnel as various different services.",
	// This pre-run is for the old commands that depend on the global AppConfig.
	// The new 'run' command handles its own configuration loading.
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// The 'run' command and 'register' don't need this global config.
		if cmd.Name() == "run" || cmd.Name() == "register" {
			return
		}

		configPath, _ := cmd.Flags().GetString("config")
		if configPath != "" {
			if err := config.LoadConfig(configPath); err != nil {
				log.Printf("WARN: Failed to load legacy config file: %v. This is only an error for old commands.", err)
			}
		} else {
			log.Printf("WARN: Config file not specified. Old commands may not work.")
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// The config flag is used by both the new `run` command and the old commands.
	rootCmd.PersistentFlags().StringP("config", "c", "config.json", "path to configuration file")
}
