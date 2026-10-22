package fingerprint_test

import (
	"math"
	"strings"
	"testing"

	"bannerprint/internal/fingerprint"
	"bannerprint/rules"
)

func newEngine(t *testing.T) *fingerprint.Engine {
	t.Helper()
	loaded, err := fingerprint.LoadFS(rules.FS, rules.Dir)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	engine, err := fingerprint.NewEngine(loaded)
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return engine
}

type expectation struct {
	protocol string
	product  string
	version  string
	osHint   string
	conf     float64
}

// TestSampleMatrix 锁定 20 条自测数据的期望输出，任何规则改动都会被它拦住。
func TestSampleMatrix(t *testing.T) {
	engine := newEngine(t)

	cases := []struct {
		name string
		in   fingerprint.Input
		want expectation
	}{
		{"ssh/ubuntu", fingerprint.Input{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}, expectation{"SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95}},
		{"http/nginx", fingerprint.Input{IP: "1.2.3.5", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"}, expectation{"HTTP", "nginx", "1.24.0", "", 0.9}},
		{"http/apache", fingerprint.Input{IP: "1.2.3.6", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"}, expectation{"HTTP", "Apache", "2.4.57", "", 0.9}},
		{"mysql/8.0", fingerprint.Input{IP: "1.2.3.7", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"}, expectation{"MySQL", "MySQL", "8.0.32", "", 0.9}},
		{"redis/err", fingerprint.Input{IP: "1.2.3.8", Port: 6379, Banner: "-ERR wrong number of arguments for 'get' command"}, expectation{"Redis", "Redis", "", "", 0.7}},
		{"ftp/proftpd", fingerprint.Input{IP: "1.2.3.9", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"}, expectation{"FTP", "ProFTPD", "1.3.7", "", 0.9}},
		{"http/jetty", fingerprint.Input{IP: "1.2.3.10", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"}, expectation{"HTTP", "Jetty", "9.4.51", "", 0.85}},
		{"ssh/debian", fingerprint.Input{IP: "1.2.3.11", Port: 22, Banner: "SSH-2.0-OpenSSH_9.3 Debian-1"}, expectation{"SSH", "OpenSSH", "9.3", "Debian", 0.95}},
		{"http/nginx-ubuntu", fingerprint.Input{IP: "1.2.3.12", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"}, expectation{"HTTP", "nginx", "1.18.0", "Ubuntu", 0.95}},
		{"http/apache-ubuntu", fingerprint.Input{IP: "1.2.3.13", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"}, expectation{"HTTP", "Apache", "2.4.41", "Ubuntu", 0.95}},
		{"mysql/5.7", fingerprint.Input{IP: "1.2.3.14", Port: 3306, Banner: "J\x00\x00\x00\n5.7.42\x00"}, expectation{"MySQL", "MySQL", "5.7.42", "", 0.9}},
		{"redis/pong", fingerprint.Input{IP: "1.2.3.15", Port: 6379, Banner: "+PONG"}, expectation{"Redis", "Redis", "", "", 0.7}},
		{"ftp/vsftpd", fingerprint.Input{IP: "1.2.3.16", Port: 21, Banner: "220 (vsFTPd 3.0.5)"}, expectation{"FTP", "vsFTPd", "3.0.5", "", 0.9}},
		{"http/nginx-8443", fingerprint.Input{IP: "1.2.3.17", Port: 8443, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3"}, expectation{"HTTP", "nginx", "1.25.3", "", 0.9}},
		{"ssh/1.99", fingerprint.Input{IP: "1.2.3.18", Port: 22, Banner: "SSH-1.99-OpenSSH_4.3"}, expectation{"SSH", "OpenSSH", "4.3", "", 0.9}},
		{"tls/clienthello", fingerprint.Input{IP: "1.2.3.19", Port: 9999, Banner: "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"}, expectation{"TLS", "", "", "", 0.6}},
		{"http/iis", fingerprint.Input{IP: "1.2.3.20", Port: 8888, Banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"}, expectation{"HTTP", "Microsoft-IIS", "10.0", "", 0.9}},
		{"redis/noauth", fingerprint.Input{IP: "1.2.3.21", Port: 6379, Banner: "-NOAUTH Authentication required."}, expectation{"Redis", "Redis", "", "", 0.7}},
		{"ftp/pure", fingerprint.Input{IP: "1.2.3.22", Port: 21, Banner: "220 Welcome to Pure-FTPd"}, expectation{"FTP", "Pure-FTPd", "", "", 0.7}},
		{"unknown/quit", fingerprint.Input{IP: "1.2.3.23", Port: 12345, Banner: "QUIT\r\n"}, expectation{"unknown", "", "", "", 0.1}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Fingerprint(tc.in)
			if got.Protocol != tc.want.protocol {
				t.Fatalf("protocol = %q, want %q", got.Protocol, tc.want.protocol)
			}
			if got.Product != tc.want.product {
				t.Errorf("product = %q, want %q", got.Product, tc.want.product)
			}
			if got.Version != tc.want.version {
				t.Errorf("version = %q, want %q", got.Version, tc.want.version)
			}
			if got.OSHint != tc.want.osHint {
				t.Errorf("os_hint = %q, want %q", got.OSHint, tc.want.osHint)
			}
			if math.Abs(got.Confidence-tc.want.conf) > 1e-9 {
				t.Errorf("confidence = %v, want %v", got.Confidence, tc.want.conf)
			}
			if got.IP != tc.in.IP || got.Port != tc.in.Port {
				t.Errorf("echo = %s:%d, want %s:%d", got.IP, got.Port, tc.in.IP, tc.in.Port)
			}
		})
	}
}

// TestRobustness 保证任何畸形输入都不会 panic，并且结果始终落在契约内。
func TestRobustness(t *testing.T) {
	engine := newEngine(t)

	cases := []struct {
		name   string
		banner string
	}{
		{"empty", ""},
		{"blank", "   \r\n\t"},
		{"binary-garbage", "\x00\x01\x02\xfe\xff"},
		{"invalid-utf8", string([]byte{0xff, 0xfe, 0xfd})},
		{"huge", strings.Repeat("A", 200_000)},
		{"partial-ssh", "SSH-2.0-"},
		{"headers-only", "Server: nginx/1.24.0"},
		{"null-bytes", "SSH-2.0-OpenSSH_8.9p1\x00\x00"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Fingerprint(fingerprint.Input{IP: "10.0.0.1", Port: 1234, Banner: tc.banner})
			if got.Protocol == "" {
				t.Fatalf("protocol must never be empty")
			}
			if got.Confidence < 0 || got.Confidence > 1 {
				t.Fatalf("confidence out of range: %v", got.Confidence)
			}
		})
	}
}

func TestUnknownFieldsAreEmpty(t *testing.T) {
	engine := newEngine(t)
	got := engine.Fingerprint(fingerprint.Input{Banner: "nope"})
	if got.Protocol != fingerprint.ProtocolUnknown {
		t.Fatalf("protocol = %q", got.Protocol)
	}
	if got.Product != "" || got.Version != "" || got.OSHint != "" {
		t.Fatalf("unknown result must not carry product/version/os: %+v", got)
	}
}
