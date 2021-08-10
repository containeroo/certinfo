package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
	"github.com/carlmjohnson/errutil"
)

var errs errutil.Slice

type hostinfo struct {
	Host  string
	Port  int
	Certs []*x509.Certificate
}

func fetchHostCertInfo(hosts []string, port int, timeout time.Duration) *[]hostinfo {
	hostnames := parseHostnames(hosts)

	returnInfo := make([]hostinfo, 0, len(*hostnames))
	for _, host := range *hostnames {
		info := hostinfo{Host: host, Port: port}
		err := info.getCerts(&timeout)
		if err != nil {
			errs.Push(err)
			continue
		}
		returnInfo = append(returnInfo, info)
	}
	return &returnInfo
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
		fmap := sprig.TxtFuncMap()
		t := template.Must(template.New("").Funcs(fmap).Parse(`
{{- range . -}}
Host: {{ .Host }}:{{ .Port }}
Certs:
    {{ range .Certs -}}
    Issuer:     {{ .Issuer.CommonName }} ({{ range .Issuer.Organization }}{{ . }}{{ end }})
    Subject:    {{ .Subject.CommonName }}
    Not Before: {{ date "Monday, 2 January 2006 at 15:04:05 (MST)" .NotBefore }}
    Not After:  {{ date "Monday, 2 January 2006 at 15:04:05 (MST)" .NotAfter }}
    DNS names:  {{ range .DNSNames }}{{ . }} {{ end }}
{{ end }}
{{ end -}}
        `))
		err := t.Execute(os.Stdout, &returnInfo)
		errs.Push(err)

	case "none":
	}
}

func checkCertExpiration(threshold time.Duration, returnInfo *[]hostinfo) {
	if threshold == 0 {
		return
	}
	deadline := time.Now().Add(threshold)
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
	if err != nil && *output != "none" {
		fmt.Fprintf(os.Stderr, "Problem running certinfo: %+v\n", err)
	}
	return hadErrors
}

func contains(list *[]string, text string) bool {
	for _, item := range *list {
		if item == text {
			return true
		}
	}
	return false
}
