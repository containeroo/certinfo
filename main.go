package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"text/template"
	"time"

	"github.com/carlmjohnson/errutil"
	"github.com/carlmjohnson/flagext"
)

const version string = "0.0.1"

var errs errutil.Slice

const usage = `Usage of certinfo (%s)

    certinfo [options] <host>...

Options:
`

type hostinfo struct {
	Host  string
	Port  int
	Certs []*x509.Certificate
}

type Configuration struct {
	Port      int
	Verbose   bool
	Timeout   time.Duration
	Threshold time.Duration
	Output    string
	Hosts     *[]string
}

func main() {
	var config *Configuration
	config = parseFlags()

	if !config.Verbose {
		log.SetOutput(io.Discard)
	}

	returnInfo := make([]hostinfo, 0, len(*config.Hosts))
	for _, host := range *config.Hosts {
		info := hostinfo{Host: host, Port: config.Port}
		err := info.getCerts(&config.Timeout)
		if err != nil {
			errs.Push(err)
			continue
		}
		returnInfo = append(returnInfo, info)
	}

	writeOutput(&config.Output, &returnInfo)
	checkCertExpiration(&config.Threshold, &returnInfo)

	exitCode := writeErrors(&config.Output)
	os.Exit(exitCode)
}

func parseFlags() (config *Configuration) {
	fl := flag.NewFlagSet("certinfo", flag.ContinueOnError)
	port := fl.Int("port", 443, "Port to look for TLS certificates on")
	verbose := fl.Bool("verbose", false, "log connections")
	timeout := fl.Int("timeout", 5, "time out on TCP dialing (in seconds)")
	threshold := fl.Int("threshold", 0, "error if a certificate expiration time (in days) is less than this")
	output := "text"
	fl.Var(
		flagext.Choice(&output, "json", "text", "none"),
		"output",
		"Output format*. One of: `text|json|none`")
	fl.Usage = func() {
		fmt.Fprintf(fl.Output(), usage, version)
		fl.PrintDefaults()
		fmt.Fprintf(fl.Output(), "\n*Output format\n%s%s\n\n",
			"If you set the output to json, ",
			"you get the complete information about the certificate!")
	}

	if err := fl.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%v", flag.ErrHelp)
		os.Exit(1)
	}

	hosts := parseHostnames(fl.Args())

	return &Configuration{
		Port:      *port,
		Verbose:   *verbose,
		Timeout:   time.Duration(*timeout) * time.Second,
		Threshold: time.Duration(*threshold*24) * time.Hour,
		Output:    output,
		Hosts:     hosts,
	}
}

func parseHostnames(hosts []string) *[]string {
	for i, h := range hosts {
		u, err := url.Parse(h)
		if err != nil {
			errs.Push(err)
			continue
		}
		if host := u.Hostname(); host != "" {
			hosts[i] = host
		}
	}
	return &hosts
}

func (h *hostinfo) getCerts(timeout *time.Duration) error {
	log.Printf("connecting to %s:%d", h.Host, h.Port)
	dialer := &net.Dialer{Timeout: *timeout}
	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		h.Host+":"+strconv.Itoa(h.Port),
		&tls.Config{
			InsecureSkipVerify: true,
		})
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		return err
	}

	pc := conn.ConnectionState().PeerCertificates
	h.Certs = make([]*x509.Certificate, 0, len(pc))
	for _, cert := range pc {
		if cert.IsCA {
			continue
		}
		h.Certs = append(h.Certs, cert)
	}

	return nil
}

func writeOutput(output *string, returnInfo *[]hostinfo) {
	switch *output {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		err := enc.Encode(&returnInfo)
		errs.Push(err)

	case "text":
		t := template.Must(template.New("").Parse(`
{{- range . -}}
Host: {{ .Host }}:{{ .Port }}
Certs:
    {{ range .Certs -}}
    Issuer: {{ .Issuer.CommonName }} {{ .Issuer.Organization }}
    Subject: {{ .Subject.CommonName }}
    Not Before: {{ .NotBefore.Format "Jan 2, 2006 3:04 PM" }}
    Not After: {{ .NotAfter.Format "Jan 2, 2006 3:04 PM" }}
    DNS names: {{ range .DNSNames }}{{ . }} {{ end }}
{{ end }}
{{ end -}}
        `))
		err := t.Execute(os.Stdout, &returnInfo)
		errs.Push(err)

	case "none":
	}
}

func checkCertExpiration(threshold *time.Duration, returnInfo *[]hostinfo) {
	if *threshold == 0 {
		return
	}
	deadline := time.Now().Add(*threshold)
	for _, hi := range *returnInfo {
		for _, c := range hi.Certs {
			if deadline.After(c.NotAfter) {
				err := fmt.Errorf("certificate for %s expires in %.2f days (at %s)",
					c.Subject.CommonName,
					c.NotAfter.Sub(time.Now()).Hours()/24,
					c.NotAfter.Format(time.RFC3339))
				errs.Push(err)
			}
		}
	}
}

func writeErrors(output *string) (exitCode int) {
	hadErrors := 0
	err := errs.Merge()
	if err != nil {
		hadErrors = 1
	}
	if *output != "none" {
		fmt.Fprintf(os.Stderr, "Problem running certinfo: %+v\n", err)
	}
	return hadErrors
}
