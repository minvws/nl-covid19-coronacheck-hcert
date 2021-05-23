package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
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

func exitWithError(err error) {
	_, _ = fmt.Fprint(os.Stderr, err.Error())
	os.Exit(1)
}
