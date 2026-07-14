// Package libXray is Hop's narrow gomobile boundary around Xray-core.
package libXray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/core"
)

const (
	bridgeVersion = 1
	goMemoryLimit = 30 * 1024 * 1024
	xrayTag       = "v26.6.27"
	xrayCommit    = "45cf2898ab12e97a55dd8f1f3d78d903340bdc9e"
)

type request struct {
	Version        int    `json:"version,omitempty"`
	Method         string `json:"method"`
	ConfigJSON     string `json:"configJSON,omitempty"`
	ConfigJson     string `json:"configJson,omitempty"`
	Config         string `json:"config,omitempty"`
	AssetDirectory string `json:"assetDirectory,omitempty"`
	DataDirectory  string `json:"datDir,omitempty"`
	TunFD          int32  `json:"tunFD,omitempty"`
	TunFd          int32  `json:"tunFd,omitempty"`
}

func (r request) configJSON() string {
	for _, value := range []string{r.ConfigJSON, r.ConfigJson, r.Config} {
		if value != "" {
			return value
		}
	}
	return ""
}

func (r request) assetDirectory() string {
	if r.AssetDirectory != "" {
		return r.AssetDirectory
	}
	return r.DataDirectory
}

func (r request) tunFD() int32 {
	if r.TunFD != 0 {
		return r.TunFD
	}
	return r.TunFd
}

type bridgeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type response struct {
	Version int          `json:"version"`
	OK      bool         `json:"ok"`
	Result  any          `json:"result,omitempty"`
	Error   *bridgeError `json:"error,omitempty"`
}

type environmentValue struct {
	value string
	set   bool
}

type environmentSnapshot map[string]environmentValue

type bridgeState struct {
	instance      *core.Instance
	configDigest  string
	collectorStop chan struct{}
	collectorDone chan struct{}
	environment   environmentSnapshot
}

var (
	// gomobile may invoke exported functions from different threads. Serialize
	// lifecycle operations so Xray's process-global instance remains singular.
	invokeMu sync.Mutex
	state    bridgeState
)

func init() {
	configureMemoryRuntime()
}

func configureMemoryRuntime() {
	debug.SetGCPercent(10)
	debug.SetMemoryLimit(goMemoryLimit)
}

// Invoke is the only gomobile API. It accepts and returns UTF-8 JSON so Swift
// never crosses the language boundary with Xray-owned objects.
func Invoke(requestJSON string) (responseJSON string) {
	defer func() {
		if recovered := recover(); recovered != nil {
			responseJSON = encodeResponse(failure("bridge_panic", fmt.Sprint(recovered)))
		}
	}()

	var req request
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return encodeResponse(failure("invalid_request", err.Error()))
	}
	if req.Version != 0 && req.Version != bridgeVersion {
		return encodeResponse(failure("unsupported_version", fmt.Sprintf("bridge version %d is unsupported", req.Version)))
	}
	if fd := req.tunFD(); fd != 0 && fd < 3 {
		return encodeResponse(failure("invalid_request", "tunFD must be at least 3"))
	}

	invokeMu.Lock()
	defer invokeMu.Unlock()

	var resp response
	switch strings.ToLower(strings.TrimSpace(req.Method)) {
	case "validate":
		resp = validate(req)
	case "start", "runxrayfromjson":
		resp = start(req)
	case "stop", "stopxray":
		resp = stop()
	case "collectmemory":
		resp = collectMemory()
	case "version":
		resp = success(map[string]any{
			"bridgeVersion": bridgeVersion,
			"goVersion":     runtime.Version(),
			"xrayCommit":    xrayCommit,
			"xrayTag":       xrayTag,
			"xrayVersion":   core.Version(),
		})
	default:
		resp = failure("unknown_method", fmt.Sprintf("unknown bridge method %q", req.Method))
	}
	return encodeResponse(resp)
}

func validate(req request) response {
	// Exact parsing constructs a short-lived core instance and can transiently
	// retain geodata. Return those pages before handing control back to Swift.
	defer debug.FreeOSMemory()

	configJSON := req.configJSON()
	if configJSON == "" {
		return failure("invalid_config", "configJSON is required")
	}

	environment := applyEnvironment(req)
	defer restoreEnvironment(environment)

	config, err := core.LoadConfig("json", strings.NewReader(configJSON))
	if err != nil {
		return failure("invalid_config", err.Error())
	}
	instance, err := core.New(config)
	if err != nil {
		return failure("invalid_config", err.Error())
	}
	if err := instance.Close(); err != nil {
		return failure("validation_cleanup_failed", err.Error())
	}
	return success(map[string]any{"valid": true})
}

func start(req request) response {
	// Xray config parsing and construction can leave sizable temporary heaps,
	// including on rejected configs. Return those pages after every attempt.
	defer debug.FreeOSMemory()

	configJSON := req.configJSON()
	if configJSON == "" {
		return failure("invalid_config", "configJSON is required")
	}
	digest := sha256.Sum256([]byte(configJSON))
	digestString := hex.EncodeToString(digest[:])
	if state.instance != nil {
		if state.configDigest == digestString && state.instance.IsRunning() {
			return success(map[string]any{"alreadyRunning": true, "running": true})
		}
		return failure("already_running", "a different Xray configuration is already running; stop it before starting another")
	}

	configureMemoryRuntime()
	environment := applyEnvironment(req)
	var instance *core.Instance
	committed := false
	defer func() {
		if committed {
			return
		}
		// Restore process-wide bridge settings even if cleanup of a partially
		// constructed core panics. Invoke's outer recovery will translate the
		// panic, but a leaked TUN_FD or asset path would poison the next start.
		defer restoreEnvironment(environment)
		if instance != nil {
			_ = instance.Close()
		}
	}()

	config, err := core.LoadConfig("json", strings.NewReader(configJSON))
	if err != nil {
		return failure("start_failed", err.Error())
	}
	instance, err = core.New(config)
	if err != nil {
		return failure("start_failed", err.Error())
	}
	if err := instance.Start(); err != nil {
		return failure("start_failed", err.Error())
	}

	collectorStop, collectorDone := startMemoryCollector()
	state = bridgeState{
		instance:      instance,
		configDigest:  digestString,
		collectorStop: collectorStop,
		collectorDone: collectorDone,
		environment:   environment,
	}
	committed = true
	return success(map[string]any{"alreadyRunning": false, "running": true})
}

func stop() response {
	// This also runs for an idempotent stop, so Swift can request an explicit
	// heap release even after the core has already torn itself down.
	defer debug.FreeOSMemory()

	if state.instance == nil {
		stopMemoryCollector()
		return success(map[string]any{"alreadyStopped": true, "running": false})
	}

	stopMemoryCollector()
	instance := state.instance
	environment := state.environment
	state = bridgeState{}
	var closeErr error
	func() {
		defer restoreEnvironment(environment)
		closeErr = instance.Close()
	}()
	if closeErr != nil {
		return failure("stop_failed", closeErr.Error())
	}
	return success(map[string]any{"alreadyStopped": false, "running": false})
}

func collectMemory() response {
	debug.FreeOSMemory()
	return success(map[string]any{"collected": true})
}

func startMemoryCollector() (chan struct{}, chan struct{}) {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				debug.FreeOSMemory()
			case <-stop:
				return
			}
		}
	}()
	return stop, done
}

func stopMemoryCollector() {
	stop := state.collectorStop
	done := state.collectorDone
	state.collectorStop = nil
	state.collectorDone = nil
	if stop == nil {
		return
	}
	close(stop)
	if done != nil {
		<-done
	}
}

func applyEnvironment(req request) environmentSnapshot {
	values := map[string]string{}
	if directory := req.assetDirectory(); directory != "" {
		values[platform.AssetLocation] = directory
		values[platform.CertLocation] = directory
	}
	if fd := req.tunFD(); fd != 0 {
		values[platform.TunFdKey] = strconv.FormatInt(int64(fd), 10)
	}

	snapshot := make(environmentSnapshot, len(values))
	for key, value := range values {
		old, set := os.LookupEnv(key)
		snapshot[key] = environmentValue{value: old, set: set}
		_ = os.Setenv(key, value)
	}
	return snapshot
}

func restoreEnvironment(snapshot environmentSnapshot) {
	for key, old := range snapshot {
		if old.set {
			_ = os.Setenv(key, old.value)
		} else {
			_ = os.Unsetenv(key)
		}
	}
}

func success(result any) response {
	return response{Version: bridgeVersion, OK: true, Result: result}
}

func failure(code, message string) response {
	return response{
		Version: bridgeVersion,
		OK:      false,
		Error:   &bridgeError{Code: code, Message: message},
	}
}

func encodeResponse(resp response) string {
	encoded, err := json.Marshal(resp)
	if err != nil {
		return `{"version":1,"ok":false,"error":{"code":"encode_failed","message":"bridge response encoding failed"}}`
	}
	return string(encoded)
}
