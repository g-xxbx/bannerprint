// Command client 读取本地 JSON 文件，调用 server 的 /fingerprint，并展示结果。
//
// 退出码：0 成功 / 1 运行期错误（网络、服务端错误）/ 2 用法或输入错误。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"bannerprint/internal/fingerprint"
	"bannerprint/internal/ingest"
)

// version 由 -ldflags "-X main.version=..." 注入。
var version = "dev"

func main() {
	file := flag.String("file", "", "input JSON file (required)")
	server := flag.String("server", envOr("FP_SERVER_URL", "http://localhost:8080"), "server base URL")
	asJSON := flag.Bool("json", false, "print raw JSON results instead of a table")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	retries := flag.Int("retries", 3, "attempts on transient failure")
	flag.Parse()

	if *file == "" {
		fmt.Fprintln(os.Stderr, "client: -file is required")
		flag.Usage()
		os.Exit(2)
	}

	f, err := os.Open(*file)
	if err != nil {
		fatalf(2, "open input: %v", err)
	}
	defer f.Close()

	inputs, err := ingest.Batch(f)
	if err != nil {
		fatalf(2, "parse input %s: %v", *file, err)
	}

	results, err := fingerprintBatch(*server, inputs, *timeout, *retries)
	if err != nil {
		fatalf(1, "%v", err)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fatalf(1, "encode output: %v", err)
		}
		return
	}
	printTable(results)
}

func fingerprintBatch(server string, inputs []fingerprint.Input, timeout time.Duration, attempts int) ([]fingerprint.Result, error) {
	if attempts < 1 {
		attempts = 1
	}

	payload, err := json.Marshal(inputs)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	endpoint := strings.TrimRight(server, "/") + "/fingerprint"
	client := &http.Client{Timeout: timeout}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			time.Sleep(time.Duration(attempt-1) * 500 * time.Millisecond)
		}

		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "bannerprint-client/"+version)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				break // 客户端错误，重试无意义
			}
			continue
		}

		var results []fingerprint.Result
		if err := json.Unmarshal(body, &results); err != nil {
			lastErr = fmt.Errorf("decode response: %w", err)
			continue
		}
		return results, nil
	}

	return nil, fmt.Errorf("fingerprint request failed after %d attempt(s): %w", attempts, lastErr)
}

func printTable(results []fingerprint.Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP, r.Port, r.Protocol, r.Product, r.Version, r.OSHint, r.Confidence)
	}
	_ = w.Flush()
}

func fatalf(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "client: "+format+"\n", args...)
	os.Exit(code)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
