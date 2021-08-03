package cmd

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"strings"
)

var rootCmd = &cobra.Command{
	Use:   "coronacheck-hcert",
	Short: "CoronaCheck EU Health Certificates",
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		exitWithError(err)
	}
}

func readConfig() error {
	configPath := viper.GetString("config")
	if configPath == "" {
		return nil
	}

	dir, file := filepath.Dir(configPath), filepath.Base(configPath)
	viper.SetConfigName(strings.TrimSuffix(file, filepath.Ext(file)))
	viper.AddConfigPath(dir)

	err := viper.ReadInConfig()
	if err != nil {
		msg := fmt.Sprintf("Could not read or apply config file %s", configPath)
		return errors.WrapPrefix(err, msg, 0)
	}

	return nil
}

func exitWithError(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
