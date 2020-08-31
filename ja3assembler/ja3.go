package ja3assembler

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

// GREASE values are random TLS extensions added to handshakes to highlight bad implementations
// that reject unknown extensions and so are likely to fail when new real features are added.
// These get added randomly per-handshake by supporting clients which unless ignored confuses the fingerprint.
// More info: https://tools.ietf.org/html/draft-ietf-tls-grease-01
var greaseTable = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// Adapted from https://github.com/honeytrap/honeytrap/blob/add50606512b3e6ad5f3951e5a110faef42bbda1/services/ja3/crypto/tls/common.go#L292
func calculateJA3(c *clientHelloMsg) string {
	// JA3 = SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
	hasher := md5.New()
	hasher.Write([]byte(fmt.Sprintf("%d,", c.vers)))

	vals := []string{}
	for _, v := range c.cipherSuites {
		vals = append(vals, fmt.Sprintf("%d", v))
	}
	hasher.Write([]byte(fmt.Sprintf("%s,", strings.Join(vals, "-"))))

	vals = []string{}
	for _, v := range c.extensions {
		if _, ok := greaseTable[v]; ok {
			continue
		}

		vals = append(vals, fmt.Sprintf("%d", v))
	}

	hasher.Write([]byte(fmt.Sprintf("%s,", strings.Join(vals, "-"))))

	vals = []string{}
	for _, v := range c.supportedCurves {
		vals = append(vals, fmt.Sprintf("%d", v))
	}
	hasher.Write([]byte(fmt.Sprintf("%s,", strings.Join(vals, "-"))))

	vals = []string{}
	for _, v := range c.supportedPoints {
		vals = append(vals, fmt.Sprintf("%d", v))
	}
	hasher.Write([]byte(fmt.Sprintf("%s", strings.Join(vals, "-"))))

	return hex.EncodeToString(hasher.Sum(nil))
}

func calculateJA3S(s *serverHelloMsg) string {
	// JA3S = SSLVersion,Cipher,SSLExtension
	hasher := md5.New()
	hasher.Write([]byte(fmt.Sprintf("%d,", s.vers)))
	hasher.Write([]byte(fmt.Sprintf("%d,", s.cipherSuite)))

	vals := []string{}
	for _, v := range s.extensions {
		if _, ok := greaseTable[v]; ok {
			continue
		}

		vals = append(vals, fmt.Sprintf("%d", v))
	}
	hasher.Write([]byte(strings.Join(vals, "-")))

	return hex.EncodeToString(hasher.Sum(nil))
}
