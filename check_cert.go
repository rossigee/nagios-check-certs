// Based on 'timewasted/go-check-certs' (Ryan Rogers).

package main

import (
	"os"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"strings"
	"time"
)

const (
	errExpiringShortly = "%s: ** '%s' (S/N %X) expires in %d hours! **"
	errExpiringSoon    = "%s: '%s' (S/N %X) expires in roughly %d days."
	errSunsetAlg       = "%s: '%s' (S/N %X) expires after the sunset date for its signature algorithm '%s'."
	okStatus           = "%s: '%s' (S/N %X) still valid for roughly %d days."
)

type sigAlgSunset struct {
	name      string    // Human readable name of signature algorithm
	sunsetsAt time.Time // Time the algorithm will be sunset
}

// sunsetSigAlgs is an algorithm to string mapping for signature algorithms
// which have been or are being deprecated.  See the following links to learn
// more about SHA1's inclusion on this list.
//
// - https://technet.microsoft.com/en-us/library/security/2880823.aspx
// - http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html
var sunsetSigAlgs = map[x509.SignatureAlgorithm]sigAlgSunset{
	x509.MD2WithRSA: sigAlgSunset{
		name:      "MD2 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.MD5WithRSA: sigAlgSunset{
		name:      "MD5 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.SHA1WithRSA: sigAlgSunset{
		name:      "SHA1 with RSA",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.DSAWithSHA1: sigAlgSunset{
		name:      "DSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.ECDSAWithSHA1: sigAlgSunset{
		name:      "ECDSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
}

var (
	hostname    = flag.String("host", "", "The hostname to check.")
	warnYears   = flag.Int("years", 0, "Warn if the certificate will expire within this many years.")
	warnMonths  = flag.Int("months", 0, "Warn if the certificate will expire within this many months.")
	warnDays    = flag.Int("days", 0, "Warn if the certificate will expire within this many days.")
	checkSigAlg = flag.Bool("check-sig-alg", true, "Verify that non-root certificates are using a good signature algorithm.")
)

type hostResult struct {
	err   error
	warn   error
	expiry string
}

func main() {
	flag.Parse()

	if *hostname == "" {
		flag.Usage()
		return
	}
	if *warnYears < 0 {
		*warnYears = 0
	}
	if *warnMonths < 0 {
		*warnMonths = 0
	}
	if *warnDays < 0 {
		*warnDays = 0
	}
	if *warnYears == 0 && *warnMonths == 0 && *warnDays == 0 {
		*warnDays = 30
	}
	var r = checkHost(*hostname)
	if r.err != nil {
		fmt.Println(fmt.Sprintf("ERROR: %s", r.err))
		os.Exit(2)
	}
	if r.warn != nil {
		fmt.Println(fmt.Sprintf("WARNING: %s", r.warn))
		os.Exit(1)
	}
	fmt.Println(fmt.Sprintf("OK: %s", r.expiry))
	os.Exit(0)
}

func checkHost(host string) (result hostResult) {
	if !strings.ContainsAny(host, ":") {
		host = fmt.Sprintf("%s:443", host)
	}

	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		result.err = err
		return
	}
	defer conn.Close()

	timeNow := time.Now()
	checkedCerts := make(map[string]struct{})
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for certNum, cert := range chain {
			if _, checked := checkedCerts[string(cert.Signature)]; checked {
				continue
			}
			checkedCerts[string(cert.Signature)] = struct{}{}

			// Check the expiration.
			expiresIn := int64(cert.NotAfter.Sub(timeNow).Hours())
			if timeNow.AddDate(*warnYears, *warnMonths, *warnDays).After(cert.NotAfter) {
				if expiresIn <= 48 {
					result.err = fmt.Errorf(errExpiringShortly, host, cert.Subject.CommonName, cert.SerialNumber, expiresIn)
				} else {
					result.warn = fmt.Errorf(errExpiringSoon, host, cert.Subject.CommonName, cert.SerialNumber, expiresIn/24)
				}
				return
			}

			// Check the signature algorithm, ignoring the root certificate.
			if alg, exists := sunsetSigAlgs[cert.SignatureAlgorithm]; *checkSigAlg && exists && certNum != len(chain)-1 {
				if cert.NotAfter.Equal(alg.sunsetsAt) || cert.NotAfter.After(alg.sunsetsAt) {
					result.err = fmt.Errorf(errSunsetAlg, host, cert.Subject.CommonName, cert.SerialNumber, alg.name)
					return
				}
			}

			// Record expiry details of main certificate for OK status
			if certNum == 0 {
				result.expiry = fmt.Sprintf(okStatus, host, cert.Subject.CommonName, cert.SerialNumber, expiresIn/24)
			}
		}
	}

	return
}
