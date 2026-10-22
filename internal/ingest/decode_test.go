package ingest

import (
	"strings"
	"testing"
)

func TestBatchArray(t *testing.T) {
	items, err := Batch(strings.NewReader(`[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-x"}]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 || items[0].IP != "1.2.3.4" || items[0].Port != 22 {
		t.Fatalf("unexpected items: %+v", items)
	}
}

func TestBatchEnvelope(t *testing.T) {
	for _, body := range []string{
		`{"items":[{"ip":"a","port":1,"banner":"x"}]}`,
		`{"data":[{"ip":"a","port":1,"banner":"x"}]}`,
		`{"batch":[{"ip":"a","port":1,"banner":"x"}]}`,
	} {
		items, err := Batch(strings.NewReader(body))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", body, err)
		}
		if len(items) != 1 {
			t.Fatalf("%s: unexpected items: %+v", body, items)
		}
	}
}

// \xNN 不是合法 JSON 转义；真实扫描数据里却常见，必须能修复后继续识别。
func TestBatchRepairsHexEscapes(t *testing.T) {
	const body = `[{"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`

	items, err := Batch(strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("unexpected items: %+v", items)
	}
	if want := "J\x00\x00\x00\n8.0.32\x00"; items[0].Banner != want {
		t.Fatalf("banner = %q, want %q", items[0].Banner, want)
	}
}

func TestBatchEmptyArray(t *testing.T) {
	items, err := Batch(strings.NewReader(`[]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("unexpected items: %+v", items)
	}
}

func TestBatchStripsBOM(t *testing.T) {
	body := "\xef\xbb\xbf" + `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-x"}]`
	items, err := Batch(strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 || items[0].IP != "1.2.3.4" {
		t.Fatalf("unexpected items: %+v", items)
	}
}

func TestBatchRejectsInvalid(t *testing.T) {
	for _, body := range []string{``, `not json`, `{"ip":`, `[{"port":"22"}]`} {
		if _, err := Batch(strings.NewReader(body)); err == nil {
			t.Fatalf("%q should fail", body)
		}
	}
}
