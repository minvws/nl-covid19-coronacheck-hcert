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
	"strings"
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

	// Local signer defaults
	flags.String("default-local-key-usages", "vaccination,test,recovery", "Default local key usages, when no keys map has been provided through configuration")
	flags.String("default-local-certificate-path", "./cert.pem", "Default local PEM encoded certificate path, when no keys map has been provided through configuration")
	flags.String("default-local-key-path", "./sk.pem", "Default local PEM encoded key file, when no keys map has been provided through configuration")

	// HSM signer
	flags.Bool("enable-hsm", false, "Enable HSM signing")
	flags.String("pkcs11-module-path", "", "Path to PKCS11 module")
	flags.String("token-label", "", "Label of token to use")
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
		config.HSMSignerConfig, err = configureHSMSigner()
	} else {
		config.LocalSignerConfig, err = configureLocalSigner()
	}

	if err != nil {
		return nil, err
	}

	return config, nil
}

func configureLocalSigner() (*localsigner.Configuration, error) {
	usageKeys := map[string]*localsigner.Key{}
	err := viper.UnmarshalKey("local-usage-keys", &usageKeys)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not unmarshal local usage keys configuration", 0)
	}

	// When no usage keys have been supplied, use the default key supplied via the command line
	if len(usageKeys) == 0 {
		fmt.Println("No keys map was supplied, falling back to default key...")

		usages := viper.GetString("default-local-key-usages")
		for _, usage := range strings.Split(usages, ",") {
			usageKeys[usage] = &localsigner.Key{
				CertificatePath: viper.GetString("default-local-certificate-path"),
				KeyPath:         viper.GetString("default-local-key-path"),
			}
		}
	}

	return &localsigner.Configuration{
		UsageKeys: usageKeys,
	}, nil
}

func configureHSMSigner() (*hsmsigner.Configuration, error) {
	// Ask for HSM user PIN entry
	fmt.Print("Enter HSM user PIN: ")
	pin, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not read PIN", 0)
	}
	fmt.Println("")

	// Load usage keys and make sure there's at least one
	usageKeys := map[string]*hsmsigner.Key{}
	err = viper.UnmarshalKey("hsm-usage-keys", &usageKeys)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not unmarshal HSM usage keys configuration", 0)
	}

	if len(usageKeys) == 0 {
		return nil, errors.Errorf("Did not encounter a HSM usage key map with at least one key present")
	}

	// Create the config
	return &hsmsigner.Configuration{
		PKCS11ModulePath: viper.GetString("pkcs11-module-path"),
		TokenLabel:       viper.GetString("token-label"),
		Pin:              string(pin),

		UsageKeys: usageKeys,
	}, nil
}
