package cmd

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer/hsmsigner"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer/localsigner"
	"github.com/minvws/nl-covid19-coronacheck-hcert/issuer/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
	"path/filepath"
	"strings"
	"syscall"
)

var serverCmd = &cobra.Command{
	Use: "server",
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
	flags.String("listen-port", "4002", "port at which to listen")

	// Local signer
	flags.String("dsc-certificate-path", "./Health_DSC_valid_for_vaccinations.pem", "DSC certficate PEM file for local signer")
	flags.String("dsc-key-path", "./Health_DSC_valid_for_vaccinations.key", "DSC EC key PEM file for local signer")

	// HSM signer
	flags.Bool("enable-hsm", false, "Enable HSM signing")
	flags.String("pkcs11-module-path", "", "Path to PKCS11 module")
	flags.String("token-label", "", "Label of token to use")

	flags.String("hsm-vaccination-certificate-path", "", "HSM vaccination PEM encoded certificate path")
	flags.Int("hsm-vaccination-key-id", 0, "HSM vaccination key ID")
	flags.String("hsm-vaccination-key-label", "", "HSM vaccination key ID")

	flags.String("hsm-test-certificate-path", "", "HSM test PEM encoded certificate path")
	flags.Int("hsm-test-key-id", 0, "HSM test key ID")
	flags.String("hsm-test-key-label", "", "HSM test key ID")

	flags.String("hsm-recovery-certificate-path", "", "HSM recovery PEM encoded certificate path")
	flags.Int("hsm-recovery-key-id", 0, "HSM recovery key ID")
	flags.String("hsm-recovery-key-label", "", "HSM recovery key ID")
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

		err = viper.ReadInConfig()
		if err != nil {
			msg := fmt.Sprintf("Could not read or apply config file %s", configPath)
			return nil, errors.WrapPrefix(err, msg, 0)
		}
	}

	config := &server.Configuration{
		ListenAddress: viper.GetString("listen-address"),
		ListenPort:    viper.GetString("listen-port"),
	}

	if viper.GetBool("enable-hsm") {
		// Ask for HSM user PIN entry
		// TODO: Encrypt in memory using github.com/awnumar/memguard
		fmt.Print("Enter HSM user PIN: ")
		pin, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			return nil, errors.WrapPrefix(err, "Could not read PIN", 0)
		}
		fmt.Println("")

		// Create the config
		config.HSMSignerConfig = &hsmsigner.Configuration{
			PKCS11ModulePath: viper.GetString("pkcs11-module-path"),
			TokenLabel:       viper.GetString("token-label"),
			Pin:              string(pin),

			KeyDescriptions: []*hsmsigner.KeyDescription{
				{
					KeyUsage:        "vaccination",
					CertificatePath: viper.GetString("hsm-vaccination-certificate-path"),
					KeyID:           viper.GetInt("hsm-vaccination-key-id"),
					KeyLabel:        viper.GetString("hsm-vaccination-key-label"),
				},
				{
					KeyUsage:        "test",
					CertificatePath: viper.GetString("hsm-test-certificate-path"),
					KeyID:           viper.GetInt("hsm-test-key-id"),
					KeyLabel:        viper.GetString("hsm-test-key-label"),
				},
				{
					KeyUsage:        "recovery",
					CertificatePath: viper.GetString("hsm-recovery-certificate-path"),
					KeyID:           viper.GetInt("hsm-recovery-key-id"),
					KeyLabel:        viper.GetString("hsm-recovery-key-label"),
				},
			},
		}
	} else {
		config.LocalSignerConfig = &localsigner.Configuration{
			DSCCertificatePath: viper.GetString("dsc-certificate-path"),
			DSCKeyPath:         viper.GetString("dsc-key-path"),
		}
	}

	return config, nil
}
