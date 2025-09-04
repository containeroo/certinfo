package output

import (
	"encoding/json"
	"fmt"
	"io"
	"text/template"
	"time"

	"github.com/containeroo/certinfo/internal/certinfo"
)

// Write renders results in the requested format to w.
func Write(w io.Writer, format string, infos []certinfo.HostInfo) {
	switch format {
	case "json":
		writeJSON(w, infos)
	case "text":
		writeText(w, infos)
	case "none":
		// no-op
	default:
		_, _ = fmt.Fprintf(w, "unknown output format %q\n", format)
	}
}

// CheckCertExpiration reports certs expiring before threshold from now.
func CheckCertExpiration(threshold time.Duration, infos []certinfo.HostInfo) {
	if threshold <= 0 {
		return
	}
	deadline := time.Now().Add(threshold)
	for _, hi := range infos {
		for _, c := range hi.Certs {
			if deadline.After(c.NotAfter) {
				err := fmt.Errorf(
					"certificate for %s expires in %.2f days (at %s)",
					c.Subject.CommonName,
					time.Until(c.NotAfter).Hours()/24,
					c.NotAfter.Format(time.RFC3339),
				)
				certinfo.PushError(err)
			}
		}
	}
}

func writeJSON(w io.Writer, infos []certinfo.HostInfo) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	// Flatten x509.Certificate to a JSON-friendly shape.
	type jsonCert struct {
		IssuerCN  string    `json:"issuer_common_name"`
		IssuerOrg []string  `json:"issuer_organization"`
		SubjectCN string    `json:"subject_common_name"`
		NotBefore time.Time `json:"not_before"`
		NotAfter  time.Time `json:"not_after"`
		DNSNames  []string  `json:"dns_names"`
	}
	type jsonHost struct {
		Host  string     `json:"host"`
		Port  int        `json:"port"`
		Certs []jsonCert `json:"certs"`
	}

	out := make([]jsonHost, 0, len(infos))
	for _, hi := range infos {
		var certs []jsonCert
		for _, c := range hi.Certs {
			certs = append(certs, jsonCert{
				IssuerCN:  c.Issuer.CommonName,
				IssuerOrg: c.Issuer.Organization,
				SubjectCN: c.Subject.CommonName,
				NotBefore: c.NotBefore,
				NotAfter:  c.NotAfter,
				DNSNames:  append([]string(nil), c.DNSNames...),
			})
		}
		out = append(out, jsonHost{Host: hi.Host, Port: hi.Port, Certs: certs})
	}
	_ = enc.Encode(out)
}

func writeText(w io.Writer, infos []certinfo.HostInfo) {
	// Provide a minimal built-in formatter for time.Time using standard library only.
	funcs := template.FuncMap{
		"format": func(t time.Time, layout string) string {
			return t.Format(layout)
		},
	}

	tpl := template.Must(template.New("text").Funcs(funcs).Parse(`
{{- range . -}}
Host: {{ .Host }}:{{ .Port }}
Certs:
{{- range .Certs }}
    Issuer:     {{ .Issuer.CommonName }} ({{ range .Issuer.Organization }}{{ . }}{{ end }})
    Subject:    {{ .Subject.CommonName }}
    Not Before: {{ format .NotBefore "Monday, 2 January 2006 at 15:04:05 (MST)" }}
    Not After:  {{ format .NotAfter  "Monday, 2 January 2006 at 15:04:05 (MST)" }}
    DNS names:  {{- if .DNSNames }} {{ range .DNSNames }}{{ . }} {{ end }}{{ else }} — {{ end }}
{{- end }}

{{- end -}}
`))
	_ = tpl.Execute(w, infos)
}
