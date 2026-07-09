package libXray

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

const minimalConfig = `{
  "log": {"loglevel": "none"},
  "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}]
}`

func call(t *testing.T, method string, fields map[string]any) response {
	t.Helper()
	request := map[string]any{"version": bridgeVersion, "method": method}
	for key, value := range fields {
		request[key] = value
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var result response
	if err := json.Unmarshal([]byte(Invoke(string(encoded))), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestValidateAndLifecycleAreIdempotent(t *testing.T) {
	t.Cleanup(func() { _ = stop() })

	if result := call(t, "validate", map[string]any{"configJSON": minimalConfig}); !result.OK {
		t.Fatalf("validate failed: %+v", result.Error)
	}
	if result := call(t, "start", map[string]any{"configJSON": minimalConfig}); !result.OK {
		t.Fatalf("start failed: %+v", result.Error)
	}
	if result := call(t, "runXrayFromJson", map[string]any{"configJson": minimalConfig}); !result.OK {
		t.Fatalf("idempotent start failed: %+v", result.Error)
	}
	if result := call(t, "stopXray", nil); !result.OK {
		t.Fatalf("stop failed: %+v", result.Error)
	}
	if result := call(t, "stop", nil); !result.OK {
		t.Fatalf("idempotent stop failed: %+v", result.Error)
	}
}

func TestInvalidRequestsReturnStructuredErrors(t *testing.T) {
	tests := []struct {
		name    string
		request string
		code    string
	}{
		{"malformed", `{`, "invalid_request"},
		{"version", `{"version":2,"method":"version"}`, "unsupported_version"},
		{"method", `{"version":1,"method":"wat"}`, "unknown_method"},
		{"removed stats", `{"version":1,"method":"stats"}`, "unknown_method"},
		{"config", `{"version":1,"method":"validate","configJSON":"{"}`, "invalid_config"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var result response
			if err := json.Unmarshal([]byte(Invoke(test.request)), &result); err != nil {
				t.Fatal(err)
			}
			if result.OK || result.Error == nil || result.Error.Code != test.code {
				t.Fatalf("got %+v, want error %q", result, test.code)
			}
		})
	}
}

func TestVersionAndMemoryMethods(t *testing.T) {
	for _, method := range []string{"version", "collectMemory"} {
		if result := call(t, method, nil); !result.OK {
			t.Fatalf("%s failed: %+v", method, result.Error)
		}
	}
}

func TestPinnedMemoryBoundedLocalGeodataParses(t *testing.T) {
	assetDirectory, err := filepath.Abs("../Geodata")
	if err != nil {
		t.Fatal(err)
	}
	config := `{
      "log":{"loglevel":"none"},
      "routing":{"domainStrategy":"IPIfNonMatch","rules":[
        {"type":"field","domain":["geosite:category-ir"],"outboundTag":"direct"},
        {"type":"field","ip":["geoip:cn","geoip:ir","geoip:private"],"outboundTag":"direct"}
      ]},
      "outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]
    }`
	result := call(t, "validate", map[string]any{
		"assetDirectory": assetDirectory,
		"configJSON":     config,
	})
	if !result.OK {
		t.Fatalf("verified local geodata was rejected: %+v", result.Error)
	}
}

func TestCategoryExcludedFromMemoryBoundedGeodataIsRejected(t *testing.T) {
	assetDirectory, err := filepath.Abs("../Geodata")
	if err != nil {
		t.Fatal(err)
	}
	config := `{
      "log":{"loglevel":"none"},
      "routing":{"rules":[
        {"type":"field","domain":["geosite:cn"],"outboundTag":"direct"}
      ]},
      "outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]
    }`
	result := call(t, "validate", map[string]any{
		"assetDirectory": assetDirectory,
		"configJSON":     config,
	})
	if result.OK || result.Error == nil || result.Error.Code != "invalid_config" {
		t.Fatalf("excluded geosite category unexpectedly validated: %+v", result)
	}
}
