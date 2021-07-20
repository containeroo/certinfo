package cmd

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var version string = "1.0.0"

var rootCmd = &cobra.Command{
	Use:     "certinfo",
	Short:   "Get information about a host certificate",
	Version: version,
	Long: `Get information about a certificate from one or more hostnames.

If the Flag --threshold|-t N is set and the certifcate expires in the next N-days,
certinfo will return the exitcode 1.

If the Flag --output|-o is set to json, certinfo will write all information about the
certificate to stdout.
`,
	Args:          cobra.MinimumNArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetBool("verbose")
		port, _ := cmd.Flags().GetInt("port")
		timeout, _ := cmd.Flags().GetInt("timeout")
		threshold, _ := cmd.Flags().GetInt("threshold")

		output, _ := cmd.Flags().GetString("output")
		outputFormat := []string{"text", "json", "none"}
		if !contains(&outputFormat, output) {
			return fmt.Errorf("output must be one of %s", strings.Join(outputFormat, ", "))
		}

		if !verbose {
			log.SetOutput(io.Discard)
		}

		returnInfo := fetchHostCertInfo(args, port, time.Duration(timeout)*time.Second)

		writeOutput(&output, returnInfo)
		checkCertExpiration(time.Duration(threshold*24)*time.Hour, returnInfo)

		exitCode := writeErrors(&output)
		os.Exit(exitCode)

		return nil
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.Flags().IntP("port", "p", 443, "Port to look for TLS certificates on")
	rootCmd.Flags().Int("timeout", 5, "time out on TCP dialing (in seconds)")
	rootCmd.Flags().IntP("threshold", "t", 0, "error if a certificate expiration time (in days) is less than this")
	rootCmd.Flags().StringP("output", "o", "text", "Output format. One of: `text|json|none`")
	rootCmd.Flags().BoolP("verbose", "v", false, "log connections")
}
