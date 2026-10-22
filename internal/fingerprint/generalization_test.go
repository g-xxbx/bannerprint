package fingerprint_test

import (
	"testing"

	"bannerprint/internal/fingerprint"
)

// 通用性语料：全部来自真实服务的典型 banner 形态，与 20 条自测数据无重合。
// 目的：证明规则不是“对着答案写的”，而是对同类协议的不同写法都成立。
// product/version/osHint 留空表示不校验该字段（只保证协议正确）。
type corpusCase struct {
	name     string
	banner   string
	protocol string
	product  string
	version  string
	osHint   string
}

func TestGeneralizationCorpus(t *testing.T) {
	engine := newEngine(t)

	cases := []corpusCase{
		// ---------- SSH ----------
		{"ssh/8.2p1-ubuntu", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "SSH", "OpenSSH", "8.2p1", "Ubuntu"},
		{"ssh/7.4", "SSH-2.0-OpenSSH_7.4", "SSH", "OpenSSH", "7.4", ""},
		{"ssh/9.6p1-ubuntu", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "SSH", "OpenSSH", "9.6p1", "Ubuntu"},
		{"ssh/6.6.1p1-ubuntu", "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13", "SSH", "OpenSSH", "6.6.1p1", "Ubuntu"},
		{"ssh/dropbear", "SSH-2.0-dropbear_2022.83", "SSH", "Dropbear", "2022.83", ""},
		{"ssh/libssh", "SSH-2.0-libssh_0.10.6", "SSH", "libssh", "0.10.6", ""},
		{"ssh/cisco", "SSH-1.5-Cisco-1.25", "SSH", "", "", ""},
		{"ssh/windows", "SSH-2.0-OpenSSH_for_Windows_8.1", "SSH", "OpenSSH", "8.1", "Windows"},
		{"ssh/generic", "SSH-2.0-ROSSSH", "SSH", "", "", ""},
		{"ssh/partial", "SSH-2.0-", "SSH", "", "", ""},

		// ---------- HTTP ----------
		{"http/nginx-lowercase", "HTTP/1.1 200 OK\r\nserver: nginx/1.22.1\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT", "HTTP", "nginx", "1.22.1", ""},
		{"http/nginx-no-version", "HTTP/1.1 301 Moved Permanently\r\nServer: nginx\r\nLocation: https://example.com/", "HTTP", "nginx", "", ""},
		{"http/apache-no-version", "HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Length: 0", "HTTP", "Apache", "", ""},
		{"http/apache-debian", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Debian)", "HTTP", "Apache", "2.4.52", "Debian"},
		{"http/jetty-parens", "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.43.v20210629)", "HTTP", "Jetty", "9.4.43", ""},
		{"http/jetty-10", "HTTP/1.1 200 OK\r\nServer: Jetty/10.0.15", "HTTP", "Jetty", "10.0.15", ""},
		{"http/iis-8.5", "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/8.5", "HTTP", "Microsoft-IIS", "8.5", ""},
		{"http/cloudflare", "HTTP/1.1 500 Internal Server Error\r\nServer: cloudflare", "HTTP", "", "", ""},
		{"http/h2", "HTTP/2 200\r\nserver: nginx/1.25.3", "HTTP", "nginx", "1.25.3", ""},
		{"http/nginx-ubuntu", "Server: nginx/1.18.0 (Ubuntu)", "HTTP", "nginx", "1.18.0", "Ubuntu"},
		{"http/openresty", "HTTP/1.1 200 OK\r\nServer: openresty/1.19.9.1", "HTTP", "openresty", "1.19.9.1", ""},
		{"http/coyote", "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1", "HTTP", "Tomcat", "1.1", ""},
		{"http/caddy", "HTTP/1.1 200 OK\r\nServer: Caddy", "HTTP", "Caddy", "", ""},
		{"http/nginx-with-powered-by", "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.1.2\r\nServer: nginx/1.20.2", "HTTP", "nginx", "1.20.2", ""},
		{"http/gunicorn", "HTTP/1.1 200 OK\r\nServer: gunicorn/20.1.0", "HTTP", "", "", ""},
		{"http/werkzeug", "HTTP/1.1 200 OK\r\nServer: Werkzeug/2.0.1 Python/3.9.7", "HTTP", "", "", ""},

		// ---------- MySQL / MariaDB ----------
		{"mysql/8.0.35-ubuntu", "J\x00\x00\x00\n8.0.35-0ubuntu0.22.04.1\x00", "MySQL", "MySQL", "8.0.35", ""},
		{"mysql/5.7.44-log", "I\x00\x00\x00\n5.7.44-log\x00", "MySQL", "MySQL", "5.7.44", ""},
		{"mysql/mariadb-10.6", "J\x00\x00\x00\n5.5.5-10.6.12-MariaDB-1:10.6.12+maria~ubu2004\x00", "MySQL", "MariaDB", "10.6.12", ""},
		{"mysql/percona", "J\x00\x00\x00\n8.0.36-28\x00", "MySQL", "MySQL", "8.0.36", ""},

		// ---------- Redis ----------
		{"redis/pong", "+PONG", "Redis", "Redis", "", ""},
		{"redis/noauth", "-NOAUTH Authentication required.", "Redis", "Redis", "", ""},
		{"redis/unknown-cmd", "-ERR unknown command 'FOO'", "Redis", "Redis", "", ""},
		{"redis/protected-mode", "-DENIED Redis is running in protected mode", "Redis", "Redis", "", ""},
		{"redis/resp-bulk", "$4\r\nPONG\r\n", "Redis", "Redis", "", ""},

		// ---------- FTP ----------
		{"ftp/vsftpd", "220 (vsFTPd 3.0.3)", "FTP", "vsFTPd", "3.0.3", ""},
		{"ftp/proftpd-no-version", "220 ProFTPD Server (Debian) [::ffff:10.0.0.1]", "FTP", "ProFTPD", "", "Debian"},
		{"ftp/microsoft", "220 Microsoft FTP Service", "FTP", "Microsoft FTP Service", "", "Windows"},
		{"ftp/filezilla", "220-FileZilla Server 1.5.1\r\n220-Please visit https://filezilla-project.org/", "FTP", "FileZilla", "1.5.1", ""},
		{"ftp/servu", "220 Serv-U FTP Server v15.1 ready...", "FTP", "Serv-U", "15.1", ""},
		{"ftp/pure", "220 Welcome to Pure-FTPd [privsep] [TLS]", "FTP", "Pure-FTPd", "", ""},
		{"ftp/generic", "220 FTP Server ready.", "FTP", "", "", ""},

		// ---------- 邮件 / 缓存 ----------
		{"smtp/postfix", "220 mail.example.com ESMTP Postfix", "SMTP", "Postfix", "", ""},
		{"smtp/exim", "220-example.com ESMTP Exim 4.96 Thu, 01 Jan 2026 00:00:00 +0000", "SMTP", "Exim", "4.96", ""},
		{"smtp/microsoft", "220 mx.example.com Microsoft ESMTP MAIL Service ready", "SMTP", "", "", ""},
		{"pop3/dovecot", "+OK Dovecot ready.", "POP3", "Dovecot", "", ""},
		{"imap/dovecot", "* OK [CAPABILITY IMAP4rev1] Dovecot ready.", "IMAP", "Dovecot", "", ""},
		{"memcached/1.6.21", "VERSION 1.6.21", "Memcached", "Memcached", "1.6.21", ""},

		// ---------- TLS ----------
		{"tls/tls12", "\x16\x03\x03\x00\x7a\x02\x00\x00\x76\x03\x03", "TLS", "", "", ""},

		// ---------- 未调优过的真实变体（用于检验泛化，而非回填答案）----------
		{"ssh/telnet-prefix", "\xff\xfd\x18SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "SSH", "OpenSSH", "8.9p1", "Ubuntu"},
		{"ssh/freebsd", "SSH-2.0-OpenSSH_9.3 FreeBSD-20230414", "SSH", "OpenSSH", "9.3", "FreeBSD"},
		{"http/tab-separated", "HTTP/1.1 200 OK\r\nServer:\tnginx/1.24.0", "HTTP", "nginx", "1.24.0", ""},
		{"http/space-version", "HTTP/1.1 200 OK\r\nServer: nginx 1.24.0", "HTTP", "nginx", "", ""},
		{"http/apache-centos", "HTTP/1.0 200 OK\r\nServer: Apache/2.2.15 (CentOS)", "HTTP", "Apache", "2.2.15", "CentOS"},
		{"http/litespeed", "HTTP/1.1 200 OK\r\nServer: LiteSpeed", "HTTP", "", "", ""},
		{"mysql/5.6", "J\x00\x00\x00\n5.6.51-log\x00", "MySQL", "MySQL", "5.6.51", ""},
		{"ftp/proftpd-debian", "220 ProFTPD 1.3.5 Server (Debian)", "FTP", "ProFTPD", "1.3.5", "Debian"},
		{"redis/noperm", "-NOPERM this user has no permissions to run the 'get' command", "Redis", "Redis", "", ""},
		{"smtp/generic", "220 smtp.example.com ESMTP", "SMTP", "", "", ""},

		// ---------- 必须判为 unknown ----------
		{"negative/quit", "QUIT\r\n", "unknown", "", "", ""},
		{"negative/binary-garbage", "\x00\x01\x02\x03garbage", "unknown", "", "", ""},
		{"negative/empty", "", "unknown", "", "", ""},
		{"negative/bare-220", "220", "unknown", "", "", ""},
		{"negative/bare-http", "HTTP", "unknown", "", "", ""},
		{"negative/random", "hello world", "unknown", "", "", ""},
	}

	var pass int
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Fingerprint(fingerprint.Input{IP: "10.1.2.3", Port: 1234, Banner: tc.banner})
			if got.Protocol != tc.protocol {
				t.Fatalf("protocol = %q, want %q (product=%q version=%q)", got.Protocol, tc.protocol, got.Product, got.Version)
			}
			if tc.product != "" && got.Product != tc.product {
				t.Errorf("product = %q, want %q", got.Product, tc.product)
			}
			if tc.version != "" && got.Version != tc.version {
				t.Errorf("version = %q, want %q", got.Version, tc.version)
			}
			if tc.osHint != "" && got.OSHint != tc.osHint {
				t.Errorf("os_hint = %q, want %q", got.OSHint, tc.osHint)
			}
			if got.Confidence < 0 || got.Confidence > 1 {
				t.Errorf("confidence out of range: %v", got.Confidence)
			}
		})
		pass++
	}
	t.Logf("corpus: %d cases", pass)
}

// 正文里出现 “Ubuntu” 不能被当成操作系统证据（只看协议头/产品指纹）。
func TestNoOSHintFromBody(t *testing.T) {
	engine := newEngine(t)
	got := engine.Fingerprint(fingerprint.Input{
		Banner: "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n<html><body>Ubuntu 22.04 LTS</body></html>",
	})
	if got.Protocol != "HTTP" {
		t.Fatalf("protocol = %q, want HTTP", got.Protocol)
	}
	if got.OSHint != "" {
		t.Fatalf("os_hint must be empty, got %q", got.OSHint)
	}
}

// 同样的输入必须给同样的结果（规则顺序稳定、无隐藏状态）。
func TestDeterminism(t *testing.T) {
	engine := newEngine(t)
	in := fingerprint.Input{IP: "1.1.1.1", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}

	first := engine.Fingerprint(in)
	for i := 0; i < 50; i++ {
		got := engine.Fingerprint(in)
		if got != first {
			t.Fatalf("non-deterministic result at iteration %d: %+v vs %+v", i, got, first)
		}
	}
}
