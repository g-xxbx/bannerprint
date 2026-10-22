package fingerprint_test

import (
	"testing"

	"bannerprint/internal/fingerprint"
)

// TestExtendedProtocols 覆盖 P1 扩展的常见服务，防止规则互相抢占。
func TestExtendedProtocols(t *testing.T) {
	engine := newEngine(t)

	cases := []struct {
		name   string
		banner string
		want   expectation
	}{
		{"smtp/postfix", "220 mail.example.com ESMTP Postfix (Ubuntu)", expectation{"SMTP", "Postfix", "", "Ubuntu", 0.95}},
		{"smtp/generic", "220 smtp.example.com ESMTP ready", expectation{"SMTP", "", "", "", 0.5}},
		{"pop3/dovecot", "+OK Dovecot ready.", expectation{"POP3", "Dovecot", "", "", 0.7}},
		{"imap/dovecot", "* OK Dovecot ready.", expectation{"IMAP", "Dovecot", "", "", 0.7}},
		{"memcached", "VERSION 1.6.9", expectation{"Memcached", "Memcached", "1.6.9", "", 0.9}},
		{"ssh/dropbear", "SSH-2.0-dropbear_2020.81", expectation{"SSH", "Dropbear", "2020.81", "", 0.9}},
		{"ssh/libssh", "SSH-2.0-libssh_0.9.6", expectation{"SSH", "libssh", "0.9.6", "", 0.9}},
		{"ssh/windows", "SSH-2.0-OpenSSH_for_Windows_8.1", expectation{"SSH", "OpenSSH", "8.1", "Windows", 0.95}},
		{"http/caddy", "HTTP/1.1 200 OK\r\nServer: Caddy", expectation{"HTTP", "Caddy", "", "", 0.7}},
		{"http/openresty", "HTTP/1.1 200 OK\r\nServer: openresty/1.21.4.1", expectation{"HTTP", "openresty", "1.21.4.1", "", 0.9}},
		{"http/tomcat", "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1", expectation{"HTTP", "Tomcat", "1.1", "", 0.9}},
		{"http/docker", "HTTP/1.1 200 OK\r\nApi-Version: 1.43", expectation{"HTTP", "Docker", "1.43", "", 0.9}},
		{"http/elasticsearch", `{"name":"n1","cluster_name":"es","version":{"number":"8.11.1"},"tagline":"You Know, for Search"}`, expectation{"HTTP", "Elasticsearch", "8.11.1", "", 0.9}},
		{"http/h2-preface", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", expectation{"HTTP", "", "", "", 0.7}},
		{"ftp/filezilla", "220-FileZilla Server 1.7.3\r\n220 Please visit https://filezilla-project.org/", expectation{"FTP", "FileZilla", "1.7.3", "", 0.9}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Fingerprint(fingerprint.Input{IP: "10.0.0.1", Port: 1, Banner: tc.banner})
			if got.Protocol != tc.want.protocol || got.Product != tc.want.product ||
				got.Version != tc.want.version || got.OSHint != tc.want.osHint {
				t.Fatalf("got %s/%s/%s/%s, want %s/%s/%s/%s",
					got.Protocol, got.Product, got.Version, got.OSHint,
					tc.want.protocol, tc.want.product, tc.want.version, tc.want.osHint)
			}
		})
	}
}
