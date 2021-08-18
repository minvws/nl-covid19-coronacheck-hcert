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
	"regexp"
	"syscall"
)

var issuanceServerCmd = &cobra.Command{
	Use: "issuance-server",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := configureIssuanceServer(cmd)
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
	rootCmd.AddCommand(issuanceServerCmd)
	setIssuanceServerFlags(issuanceServerCmd)
}

func setIssuanceServerFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.SortFlags = false

	flags.String("config", "", "path to configuration file (JSON, TOML, YAML or INI)")
	flags.String("listen-address", "localhost", "address at which to listen")
	flags.String("listen-port", "4002", "port at which to listen")
	flags.String("issuer-country-code", "NL", "the country code that is used as CWT issuer")

	// Local signer
	flags.String("local-vaccination-certificate-path", "./cert.pem", "Local vaccination PEM encoded certificate path")
	flags.String("local-vaccination-key-path", "./sk.pem", "Local vaccination PEM encoded key file")

	flags.String("local-test-certificate-path", "./cert.pem", "Local test PEM encoded certificate path")
	flags.String("local-test-key-path", "./sk.pem", "Local test PEM encoded key file")

	flags.String("local-recovery-certificate-path", "./cert.pem", "Local recovery PEM encoded certificate path")
	flags.String("local-recovery-key-path", "./sk.pem", "Local recovery PEM encoded key file")

	// HSM signer
	flags.Bool("enable-hsm", false, "Enable HSM signing")
	flags.String("pkcs11-module-path", "", "Path to PKCS11 module")
	flags.String("token-label", "", "Label of token to use")

	flags.String("hsm-vaccination-certificate-path", "", "HSM vaccination PEM encoded certificate path")
	flags.Int("hsm-vaccination-key-id", 0, "HSM vaccination key ID")
	flags.String("hsm-vaccination-key-label", "", "HSM vaccination key label")

	flags.String("hsm-test-certificate-path", "", "HSM test PEM encoded certificate path")
	flags.Int("hsm-test-key-id", 0, "HSM test key ID")
	flags.String("hsm-test-key-label", "", "HSM test key label")

	flags.String("hsm-recovery-certificate-path", "", "HSM recovery PEM encoded certificate path")
	flags.Int("hsm-recovery-key-id", 0, "HSM recovery key ID")
	flags.String("hsm-recovery-key-label", "", "HSM recovery key label")
}

func configureIssuanceServer(cmd *cobra.Command) (*server.Configuration, error) {
	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		return nil, err
	}

	err = readConfig()
	if err != nil {
		return nil, err
	}

	issCC := viper.GetString("issuer-country-code")
	if !regexp.MustCompile("^[A-Z]{2}$").MatchString(issCC) {
		return nil, errors.Errorf("Invalid ISO 3166-1 alpha-2 issuer country code")
	}

	config := &server.Configuration{
		ListenAddress:     viper.GetString("listen-address"),
		ListenPort:        viper.GetString("listen-port"),
		IssuerCountryCode: viper.GetString("issuer-country-code"),
	}

	if viper.GetBool("enable-hsm") {
		hsmConfig, err := configureHSMSigner()
		if err != nil {
			return nil, err
		}

		config.HSMSignerConfig = hsmConfig
	} else {
		config.LocalSignerConfig = configureLocalSigner()
	}

	return config, nil
}

func configureLocalSigner() *localsigner.Configuration {
	return &localsigner.Configuration{
		KeyDescriptions: []*localsigner.KeyDescription{
			{
				KeyUsage:        "vaccination",
				CertificatePath: viper.GetString("local-vaccination-certificate-path"),
				KeyPath:         viper.GetString("local-vaccination-key-path"),
			},
			{
				KeyUsage:        "test",
				CertificatePath: viper.GetString("local-test-certificate-path"),
				KeyPath:         viper.GetString("local-test-key-path"),
			},
			{
				KeyUsage:        "recovery",
				CertificatePath: viper.GetString("local-recovery-certificate-path"),
				KeyPath:         viper.GetString("local-recovery-key-path"),
			},
		},
	}
}

func configureHSMSigner() (*hsmsigner.Configuration, error) {
	// Ask for HSM user PIN entry
	fmt.Print("Enter HSM user PIN: ")
	pin, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not read PIN", 0)
	}
	fmt.Println("")

	// Create the config
	return &hsmsigner.Configuration{
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
	}, nil
}
