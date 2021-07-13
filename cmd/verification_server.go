package cmd

import (
	"github.com/minvws/nl-covid19-coronacheck-hcert/verifier/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serverCmd = &cobra.Command{
	Use: "verification-server",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := configureServer(cmd)
		if err != nil {
			exitWithError(err)
		}

		err = server.Run(config)
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
	flags.String("listen-port", "4003", "port at which to listen")

	flags.String("public-keys-path", "./public_keys.json", "path to public keys JSON file")
}

func configureServer(cmd *cobra.Command) (*server.Configuration, error) {
	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		return nil, err
	}

	err = readConfig()
	if err != nil {
		return nil, err
	}

	config := &server.Configuration{
		ListenAddress: viper.GetString("listen-address"),
		ListenPort:    viper.GetString("listen-port"),

		PublicKeysPath: viper.GetString("public-keys-path"),
	}

	return config, nil
}
