package libXray

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"

	"github.com/xtls/xray-core/common/platform"
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

func TestConfigureMemoryRuntimeAppliesPolicy(t *testing.T) {
	previousGCPercent := debug.SetGCPercent(99)
	previousMemoryLimit := debug.SetMemoryLimit(2 * goMemoryLimit)
	t.Cleanup(func() {
		debug.SetGCPercent(previousGCPercent)
		debug.SetMemoryLimit(previousMemoryLimit)
	})

	configureMemoryRuntime()
	if got := debug.SetGCPercent(10); got != 10 {
		t.Fatalf("GC percent = %d, want 10", got)
	}
	if got := debug.SetMemoryLimit(goMemoryLimit); got != goMemoryLimit {
		t.Fatalf("memory limit = %d, want %d", got, goMemoryLimit)
	}
}

func TestFailedStartRestoresEnvironmentAndLeavesNoRuntimeState(t *testing.T) {
	t.Cleanup(func() { _ = stop() })
	t.Setenv(platform.AssetLocation, "original-assets")
	t.Setenv(platform.CertLocation, "original-certs")
	t.Setenv(platform.TunFdKey, "91")

	result := start(request{
		ConfigJSON:     "{",
		AssetDirectory: "temporary-assets",
		TunFD:          92,
	})
	if result.OK || result.Error == nil || result.Error.Code != "start_failed" {
		t.Fatalf("invalid start returned %+v", result)
	}

	for key, want := range map[string]string{
		platform.AssetLocation: "original-assets",
		platform.CertLocation:  "original-certs",
		platform.TunFdKey:      "91",
	} {
		if got := os.Getenv(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if state.instance != nil || state.collectorStop != nil || state.collectorDone != nil || state.environment != nil {
		t.Fatalf("failed start retained runtime state: %+v", state)
	}
}

func TestFailedCoreStartClosesPartialInstanceAndRestoresEnvironment(t *testing.T) {
	t.Cleanup(func() { _ = stop() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	config := fmt.Sprintf(`{
      "log":{"loglevel":"none"},
      "inbounds":[{
        "listen":"127.0.0.1",
        "port":%d,
        "protocol":"dokodemo-door",
        "settings":{"address":"127.0.0.1","port":80,"network":"tcp"}
      }],
      "outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]
    }`, port)

	// Exact validation constructs and closes the core without opening the
	// listener, proving the failure below occurs after instance construction.
	if result := validate(request{ConfigJSON: config}); !result.OK {
		t.Fatalf("occupied-port config did not construct: %+v", result.Error)
	}

	t.Setenv(platform.AssetLocation, "original-assets")
	t.Setenv(platform.CertLocation, "original-certs")
	t.Setenv(platform.TunFdKey, "91")
	result := start(request{
		ConfigJSON:     config,
		AssetDirectory: "temporary-assets",
		TunFD:          92,
	})
	if result.OK || result.Error == nil || result.Error.Code != "start_failed" {
		t.Fatalf("occupied-port start returned %+v", result)
	}

	for key, want := range map[string]string{
		platform.AssetLocation: "original-assets",
		platform.CertLocation:  "original-certs",
		platform.TunFdKey:      "91",
	} {
		if got := os.Getenv(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if state.instance != nil || state.collectorStop != nil || state.collectorDone != nil || state.environment != nil {
		t.Fatalf("failed core start retained runtime state: %+v", state)
	}
	if result := start(request{ConfigJSON: minimalConfig}); !result.OK {
		t.Fatalf("a clean start after rollback failed: %+v", result.Error)
	}
	if result := stop(); !result.OK {
		t.Fatalf("stop after rollback recovery failed: %+v", result.Error)
	}
}

func TestAlreadyStoppedStopCleansUpMemoryCollector(t *testing.T) {
	if state.instance != nil || state.collectorStop != nil || state.collectorDone != nil {
		t.Fatalf("test started with live bridge state: %+v", state)
	}

	state.collectorStop, state.collectorDone = startMemoryCollector()
	done := state.collectorDone
	result := stop()
	if !result.OK {
		t.Fatalf("idempotent stop failed: %+v", result.Error)
	}
	if state.collectorStop != nil || state.collectorDone != nil {
		t.Fatalf("collector channels were retained: %+v", state)
	}
	select {
	case <-done:
	default:
		t.Fatal("stop returned before the memory collector exited")
	}

	if result := stop(); !result.OK {
		t.Fatalf("second idempotent stop failed: %+v", result.Error)
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
