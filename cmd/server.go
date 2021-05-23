package cmd

import (
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"path/filepath"
	"strings"
)

var serverCmd = &cobra.Command{
	Use: "server",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := configureServer(cmd)
		if err != nil {
			exitWithError(err)
		}

		err = server.Serve(config)
		if err != nil {
			exitWithError(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	setServerFlags(serverCmd)
}

func setServerFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.SortFlags = false

	flags.String("config", "", "path to configuration file (JSON, TOML, YAML or INI)")
	flags.String("listen-address", "localhost", "address at which to listen")
	flags.String("listen-port", "4002", "port at which to listen")
	flags.String("dsc-certificate-path", "./Health_DSC_valid_for_vaccinations.pem", "DSC certficate PEM file")
	flags.String("dsc-key-path", "./Health_DSC_valid_for_vaccinations.key", "DSC EC key PEM file")
}

func configureServer(cmd *cobra.Command) (*server.Configuration, error) {
	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		return nil, err
	}

	configPath := viper.GetString("config")
	if configPath != "" {
		dir, file := filepath.Dir(configPath), filepath.Base(configPath)
		viper.SetConfigName(strings.TrimSuffix(file, filepath.Ext(file)))
		viper.AddConfigPath(dir)
	}

	config := &server.Configuration{
		ListenAddress: viper.GetString("listen-address"),
		ListenPort:    viper.GetString("listen-port"),

		DSCCertificatePath: viper.GetString("dsc-certificate-path"),
		DSCKeyPath:         viper.GetString("dsc-key-path"),
	}

	return config, nil
}
