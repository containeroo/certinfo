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

var version string = "1.1.0"

var rootCmd = &cobra.Command{
	Use:           "certinfo HOSTNAME [HOSTNAME ...]",
	Short:         "Get information about the certificate from one or more hostnames.",
	Version:       version,
	Long:          `Get information about the certificate from one or more hostnames.`,
	Args:          cobra.MinimumNArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetBool("verbose")
		port, _ := cmd.Flags().GetInt("port")
		timeout, _ := cmd.Flags().GetInt("timeout")
		retry, _ := cmd.Flags().GetInt("retry")
		threshold, _ := cmd.Flags().GetInt("threshold")

		output, _ := cmd.Flags().GetString("output")
		outputFormat := []string{"text", "json", "none"}
		if !contains(&outputFormat, output) {
			return fmt.Errorf("output must be one of %s", strings.Join(outputFormat, ", "))
		}

		if !verbose {
			log.SetOutput(io.Discard)
		}

		returnInfo := fetchHostCertInfo(args, port, time.Duration(timeout)*time.Second, retry)

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
	rootCmd.Flags().IntP("port", "p", 443, "port to look for TLS certificates on")
	rootCmd.Flags().Int("timeout", 5, "timeout on TCP dialing (in seconds)")
	rootCmd.Flags().IntP("retry", "r", 5, "retry request if transient problems occur")
	rootCmd.Flags().IntP("threshold", "t", 0, "exit certinfo with exit code 1 if a certificate expiration time is less than this (in days)")
	rootCmd.Flags().StringP("output", "o", "text", "output format, one of: `text|json|none`.\nIf set to \"json\", certinfo will output all information about the certificate")
	rootCmd.Flags().BoolP("verbose", "v", false, "log connections")
}
