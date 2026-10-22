package fingerprint_test

import (
	"math/rand"
	"strings"
	"testing"

	"bannerprint/internal/fingerprint"
)

// 随机字节流下引擎必须：不 panic、协议非空、置信度在 [0,1]。
// 这是防止“只对见过的样本成立”的最直接约束。
func TestRandomBannersNeverPanic(t *testing.T) {
	engine := newEngine(t)
	rng := rand.New(rand.NewSource(20261022))

	for i := 0; i < 2000; i++ {
		buf := make([]byte, rng.Intn(300))
		_, _ = rng.Read(buf)

		got := engine.Fingerprint(fingerprint.Input{
			IP:     "10.0.0.1",
			Port:   rng.Intn(65535) + 1,
			Banner: string(buf),
		})

		if got.Protocol == "" {
			t.Fatalf("iteration %d: empty protocol for banner %q", i, buf)
		}
		if got.Confidence < 0 || got.Confidence > 1 {
			t.Fatalf("iteration %d: confidence %v out of range", i, got.Confidence)
		}
		if got.Protocol == fingerprint.ProtocolUnknown {
			if got.Product != "" || got.Version != "" || got.OSHint != "" {
				t.Fatalf("iteration %d: unknown result must be blank: %+v", i, got)
			}
		}
	}
}

// 超长 banner 不能拖垮引擎，也不能让结果失真。
func TestHugeBanner(t *testing.T) {
	engine := newEngine(t)

	banner := "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5 " + strings.Repeat("A", 1<<20)
	got := engine.Fingerprint(fingerprint.Input{Banner: banner})
	if got.Protocol != "SSH" || got.Product != "OpenSSH" || got.Version != "9.6p1" {
		t.Fatalf("unexpected result for huge banner: %+v", got)
	}
}

// 蜕变测试：不改语义的变形（大小写、空白、换行风格、重复）不应改变识别结果。
// 这比“逐条断言期望值”更独立——它检查的是规则的不变性，而不是我的标注。
func TestMetamorphicTextBanners(t *testing.T) {
	engine := newEngine(t)

	banners := []string{
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
		"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Ubuntu)",
		"HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51",
		"220 ProFTPD 1.3.7 Server (ProFTPD)",
		"220 (vsFTPd 3.0.5)",
		"220 mail.example.com ESMTP Postfix",
		"+OK Dovecot ready.",
		"-NOAUTH Authentication required.",
		"VERSION 1.6.21",
	}

	variants := map[string]func(string) string{
		"upper":    strings.ToUpper,
		"trailing": func(s string) string { return s + "\x00 \t" },
		"leading":  func(s string) string { return " \r\n" + s },
		"lf-only":  func(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") },
		"duplicated": func(s string) string {
			return s + "\r\n" + s
		},
	}

	for _, banner := range banners {
		base := engine.Fingerprint(fingerprint.Input{IP: "1.1.1.1", Port: 80, Banner: banner})
		for name, transform := range variants {
			got := engine.Fingerprint(fingerprint.Input{IP: "1.1.1.1", Port: 80, Banner: transform(banner)})
			// 大小写变形只可能影响 version 的字面大小写（如 8.9P1），其余字段应完全一致。
			if got.Protocol != base.Protocol || got.Product != base.Product ||
				got.OSHint != base.OSHint || got.Confidence != base.Confidence ||
				!strings.EqualFold(got.Version, base.Version) {
				t.Errorf("%s/%s: %+v, want %+v", banner, name, got, base)
			}
		}
	}
}

// 混合批次：协议互不串味，结果与输入一一对应。
func TestMixedBatchOrder(t *testing.T) {
	engine := newEngine(t)

	inputs := []fingerprint.Input{
		{IP: "1", Port: 22, Banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"},
		{IP: "2", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Debian)"},
		{IP: "3", Port: 3306, Banner: "J\x00\x00\x00\n8.0.35\x00"},
		{IP: "4", Port: 6379, Banner: "-NOAUTH Authentication required."},
		{IP: "5", Port: 21, Banner: "220 (vsFTPd 3.0.3)"},
		{IP: "6", Port: 25, Banner: "220 mail.example.com ESMTP Postfix"},
		{IP: "7", Port: 9999, Banner: "\x16\x03\x03\x00\x7a\x02\x00\x00\x76\x03\x03"},
		{IP: "8", Port: 1, Banner: "QUIT"},
	}
	want := []string{"SSH", "HTTP", "MySQL", "Redis", "FTP", "SMTP", "TLS", "unknown"}

	for i, in := range inputs {
		got := engine.Fingerprint(in)
		if got.Protocol != want[i] {
			t.Fatalf("item %d: protocol = %q, want %q", i, got.Protocol, want[i])
		}
		if got.IP != in.IP || got.Port != in.Port {
			t.Fatalf("item %d: input echo mismatch", i)
		}
	}
}
