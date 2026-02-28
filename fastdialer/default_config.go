package fastdialer

import (
	"crypto/tls"
	"io"
	"os"
	"sync"

	ztls "github.com/zmap/zcrypto/tls"
)

// getUnsafeCipherSuites returns a list of all cipher suites that are considered
// unsafe by the Go standard library. This includes all cipher suites that are
// not included in the default cipher suite list.
func getUnsafeCipherSuites() []uint16 {
	// Copied from: https://github.com/projectdiscovery/nuclei/pull/4753/files
	unsafeCipherSuites := make([]uint16, 0, len(tls.InsecureCipherSuites())+len(tls.CipherSuites()))
	for _, suite := range tls.InsecureCipherSuites() {
		unsafeCipherSuites = append(unsafeCipherSuites, suite.ID)
	}
	for _, suite := range tls.CipherSuites() {
		unsafeCipherSuites = append(unsafeCipherSuites, suite.ID)
	}

	return unsafeCipherSuites
}

var (
	keyLogOnce   sync.Once
	keyLogWriter io.Writer
)

func getKeyLogWriter() io.Writer {
	keyLogOnce.Do(func() {
		if path := os.Getenv("SSLKEYLOGFILE"); path != "" {
			if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
				keyLogWriter = f
			}
		}
	})
	return keyLogWriter
}

// DefaultTLSConfig is a default TLS configuration that is used by the
// fastdialer.
var DefaultTLSConfig = &tls.Config{
	Renegotiation:      tls.RenegotiateOnceAsClient,
	InsecureSkipVerify: true,
	MinVersion:         tls.VersionTLS10,
	CipherSuites:       getUnsafeCipherSuites(),
	KeyLogWriter:       getKeyLogWriter(),
}

// DefaultZTLSConfig is a default ZTLS configuration that is used by the
// fastdialer.
var DefaultZTLSConfig = &ztls.Config{
	InsecureSkipVerify: true,
	MinVersion:         ztls.VersionTLS10,
	CipherSuites:       getUnsafeCipherSuites(),
}
