# certinfo

Get informations about the certificate from one or more hosts.

If the Flag `--threshold`|`-t` `N` is set and the certifcate expires in the next `N`-days,
certinfo will return the exitcode 1.

If the Flag `--output`|`-o` is set to `json`, certinfo will write all information about the
certificate to stdout.

## Usage

```text
Usage:
  certinfo [flags]

Flags:
  -h, --help                    help for certinfo
  -o, --output text|json|none   Output format. One of: text|json|none (default "text")
  -p, --port int                Port to look for TLS certificates on (default 443)
  -t, --threshold int           error if a certificate expiration time (in days) is less than this
      --timeout int             time out on TCP dialing (in seconds) (default 5)
  -v, --verbose                 log connections
      --version                 version for certinfo
```

## Examples

### get certificate for google.io

```bash
certinfo google.io
```

output:

```console
Host: google.io:443
Certs:
    Issuer: GTS CA 1C3 [Google Trust Services LLC]
    Subject: *.google.io
    Not Before: Jun 22, 2021 5:47 PM
    Not After: Sep 14, 2021 5:47 PM
    DNS names: *.google.io google.io
```

### get certificate from google.io and output the complete certificate information as json

```bash
certinfo --output json --verbose google.io
```

output:

```console
2018/11/04 19:19:15 connecting to google.io:443
[
  {
    "Host": "google.io",
    "Port": 443,
    "Certs": [
      {
        // snip many fields!
      }
    ]
  }
]
```

### get certificate for google.io and check if the certificate is valid for more than 30 days

```bash
certinfo --output none --threshold 30 google.io
```

output:

there is no output if the certificate expires more than 30 days

### get certificate for google.io and check if the certificate is valid for more than 20 days

```bash
certinfo --output none --threshold 20 google.io
```

output:

```console
Problem running certinfo: certificate for *.google.io expires in 60.10 days (at 2021-09-14T17:47:02Z)
```

### get certificate for google.io and extract the expiration date

```bash
certinfo --output json example.io | jq -r '.[].Certs[].NotBefore'
```

output:

```console
2021-06-22T17:47:03Z
```

### using in a cronjob with healthchecks.io

```text
0 2 * * * root certinfo google.io --output none; curl -fsS -X POST "https://healthchecks.example.com/ping/<UID>$([ echo $? != 0 ] && echo -n /fail)" > /dev/null
```

inspired by [certinfo](https://github.com/carlmjohnson/certinfo)
