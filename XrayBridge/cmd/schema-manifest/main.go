// Command schema-manifest generates Hop's client-schema manifest directly from
// the JSON-tagged Xray config structs at the pinned Xray-core source tree.
//
// It intentionally does not generate a general-purpose JSON Schema. Xray's
// config layer contains RawMessage unions and custom UnmarshalJSON methods that
// cannot be represented faithfully by reflection alone. The generated manifest
// combines the struct-derived field graph with reviewed client-only unions,
// enums, applicability, and Hop policy annotations.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	coreVersion       = "v26.6.27"
	coreCommit        = "45cf2898ab12e97a55dd8f1f3d78d903340bdc9e"
	coreModuleVersion = "v1.260327.1-0.20260627131803-45cf2898ab12"
	formatVersion     = 1
)

type manifest struct {
	FormatVersion int                         `json:"formatVersion"`
	Generator     generatorInfo               `json:"generator"`
	Core          coreInfo                    `json:"core"`
	Scope         scopeInfo                   `json:"scope"`
	Roots         map[string]section          `json:"roots"`
	Protocols     map[string]protocolSection  `json:"outboundProtocols"`
	Transports    map[string]transportSection `json:"transports"`
	FinalMask     finalMaskSection            `json:"finalMask"`
	DynamicShapes map[string]dynamicShape     `json:"dynamicShapes"`
	Definitions   map[string]definition       `json:"definitions"`
	Annotations   annotations                 `json:"annotations"`
}

type generatorInfo struct {
	Command string `json:"command"`
	Method  string `json:"method"`
}

type coreInfo struct {
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	Module        string `json:"module"`
	ModuleVersion string `json:"moduleVersion"`
	SourcePackage string `json:"sourcePackage"`
}

type scopeInfo struct {
	Applicability string   `json:"applicability"`
	Includes      []string `json:"includes"`
	Excludes      []string `json:"excludes"`
}

type section struct {
	Ref           string   `json:"$ref"`
	Applicability string   `json:"applicability"`
	Aliases       []string `json:"aliases,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

type protocolSection struct {
	Ref           string   `json:"settingsRef"`
	Applicability string   `json:"applicability"`
	Aliases       []string `json:"aliases,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

type transportSection struct {
	SettingsField string   `json:"settingsField"`
	Ref           string   `json:"settingsRef"`
	Applicability string   `json:"applicability"`
	Aliases       []string `json:"aliases,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

type finalMaskSection struct {
	Ref string                       `json:"$ref"`
	TCP map[string]finalMaskTypeSpec `json:"tcpTypes"`
	UDP map[string]finalMaskTypeSpec `json:"udpTypes"`
}

type finalMaskTypeSpec struct {
	Ref           string `json:"settingsRef"`
	Applicability string `json:"applicability"`
}

type dynamicShape struct {
	Location      string                  `json:"location"`
	Discriminator string                  `json:"discriminator,omitempty"`
	Ref           string                  `json:"$ref,omitempty"`
	Variants      map[string]dynamicValue `json:"variants,omitempty"`
	Notes         []string                `json:"notes,omitempty"`
}

type dynamicValue struct {
	Ref           string   `json:"$ref"`
	Applicability string   `json:"applicability"`
	Aliases       []string `json:"aliases,omitempty"`
}

type definition struct {
	JSONTypes     []string               `json:"jsonTypes"`
	Applicability string                 `json:"applicability"`
	Source        sourceLocation         `json:"source"`
	Fields        map[string]fieldSchema `json:"fields,omitempty"`
	Inherits      []string               `json:"inherits,omitempty"`
	OneOf         []typeUse              `json:"oneOf,omitempty"`
	Notes         []string               `json:"notes,omitempty"`
}

type sourceLocation struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

type fieldSchema struct {
	GoField       string   `json:"goField"`
	JSONTypes     []string `json:"jsonTypes"`
	Ref           string   `json:"$ref,omitempty"`
	Items         *typeUse `json:"items,omitempty"`
	Additional    *typeUse `json:"additionalProperties,omitempty"`
	Optional      bool     `json:"optional"`
	Enum          []string `json:"enum,omitempty"`
	Applicability string   `json:"applicability"`
	Annotations   []string `json:"annotations,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

type typeUse struct {
	JSONTypes []string `json:"jsonTypes"`
	Ref       string   `json:"$ref,omitempty"`
	GoType    string   `json:"goType,omitempty"`
	Items     *typeUse `json:"items,omitempty"`
}

type annotations struct {
	SecretPaths           []string       `json:"secretPaths"`
	SecurityCriticalPaths []string       `json:"securityCriticalPaths"`
	MemorySensitivePaths  []string       `json:"memorySensitivePaths"`
	HopManagedPaths       []string       `json:"hopManagedPaths"`
	RejectedPaths         []rejectedPath `json:"rejectedPaths"`
}

type rejectedPath struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type parsedType struct {
	Name       string
	Struct     *ast.StructType
	SourceFile string
	Line       int
}

type enumOverlay struct {
	Values []string
	Notes  []string
}

var seedTypes = []string{
	"Config", "OutboundDetourConfig", "StreamConfig", "ProxyConfig", "MuxConfig",
	"VLessOutboundConfig", "VLessOutboundVnext", "VLessReverseConfig",
	"VMessOutboundConfig", "VMessOutboundTarget", "VMessAccount",
	"TrojanClientConfig", "TrojanServerTarget",
	"ShadowsocksClientConfig", "ShadowsocksServerTarget", "ShadowsocksUserConfig",
	"SocksClientConfig", "SocksRemoteConfig", "SocksAccount",
	"HTTPClientConfig", "HTTPRemoteConfig", "HTTPAccount",
	"WireGuardConfig", "WireGuardPeerConfig", "HysteriaClientConfig",
	"FreedomConfig", "Fragment", "Noise", "FreedomFinalRuleConfig",
	"BlackholeConfig", "NoneResponse", "HTTPResponse", "DNSOutboundConfig", "DNSOutboundRuleConfig", "LoopbackConfig",
	"KCPConfig", "TCPConfig", "WebSocketConfig", "HttpUpgradeConfig", "SplitHTTPConfig",
	"XmuxConfig", "HysteriaConfig", "UdpHop", "Masquerade", "GRPCConfig",
	"TLSConfig", "TLSCertConfig", "REALITYConfig", "LimitFallback", "SocketConfig",
	"CustomSockoptConfig", "HappyEyeballsConfig", "QuicParamsConfig", "FinalMask", "Mask",
	"HeaderCustomTCP", "TCPItem", "FragmentMask", "HeaderCustomUDP", "UDPItem",
	"NoOpConnectionAuthenticator", "Authenticator", "AuthenticatorRequest", "AuthenticatorResponse",
	"CustomTransform", "CustomTransformArg", "MkcpLegacy", "NoiseMask", "NoiseItem",
	"Salamander", "Sudoku", "Xdns", "Xicmp", "Realm",
	"DNSConfig", "NameServerConfig", "RouterConfig", "RawFieldRule", "RouterRule",
	"WebhookRuleConfig", "BalancingRule", "StrategyConfig", "strategyEmptyConfig", "strategyLeastLoadConfig",
	"PolicyConfig", "Policy", "SystemPolicy", "ObservatoryConfig", "BurstObservatoryConfig",
	"healthCheckSettings", "FakeDNSPoolElementConfig", "VersionConfig", "GeodataConfig",
	"GeodataAssetConfig", "LogConfig", "StatsConfig",
}

var enumOverlays = map[string]enumOverlay{
	"OutboundDetourConfig.targetStrategy": {Values: []string{"", "asis", "useip", "useipv4", "useipv6", "useipv4v6", "useipv6v4", "forceip", "forceipv4", "forceipv6", "forceipv4v6", "forceipv6v4"}},
	"MuxConfig.xudpProxyUDP443":           {Values: []string{"", "reject", "allow", "skip"}},
	"StreamConfig.network":                {Values: []string{"raw", "tcp", "xhttp", "splithttp", "kcp", "mkcp", "grpc", "ws", "websocket", "httpupgrade", "hysteria"}, Notes: []string{"h2, h3, http, and quic are parsed only to return a removed-feature error."}},
	"StreamConfig.security":               {Values: []string{"", "none", "tls", "reality"}, Notes: []string{"xtls is parsed only to return a removed-feature error."}},
	"SplitHTTPConfig.mode":                {Values: []string{"", "auto", "packet-up", "stream-up", "stream-one"}},
	"SplitHTTPConfig.xPaddingPlacement":   {Values: []string{"", "cookie", "header", "query", "queryInHeader"}},
	"SplitHTTPConfig.xPaddingMethod":      {Values: []string{"", "repeat-x", "tokenish"}},
	"SplitHTTPConfig.sessionIDPlacement":  {Values: []string{"", "path", "cookie", "header", "query"}},
	"SplitHTTPConfig.seqPlacement":        {Values: []string{"", "path", "cookie", "header", "query"}},
	"SplitHTTPConfig.uplinkDataPlacement": {Values: []string{"", "auto", "body", "cookie", "header"}},
	"TLSCertConfig.usage":                 {Values: []string{"encipherment", "verify", "issue"}},
	"SocketConfig.tproxy":                 {Values: []string{"", "tproxy", "redirect"}},
	"SocketConfig.domainStrategy":         {Values: []string{"", "asis", "useip", "useipv4", "useipv6", "useipv4v6", "useipv6v4", "forceip", "forceipv4", "forceipv6", "forceipv4v6", "forceipv6v4"}},
	"SocketConfig.addressPortStrategy":    {Values: []string{"", "none", "srvportonly", "srvaddressonly", "srvportandaddress", "txtportonly", "txtaddressonly", "txtportandaddress"}},
	"HeaderCustomUDP.mode":                {Values: []string{"", "prefix", "standalone"}},
	"MkcpLegacy.header":                   {Values: []string{"", "dns", "dtls", "srtp", "utp", "wechat", "wireguard"}},
	"RouterConfig.domainStrategy":         {Values: []string{"AsIs", "IPIfNonMatch", "IPOnDemand"}, Notes: []string{"Comparison is case-insensitive; unknown values fall back to AsIs."}},
	"StrategyConfig.type":                 {Values: []string{"", "random", "leastping", "roundrobin", "leastload"}},
	"DNSConfig.queryStrategy":             {Values: []string{"UseIP", "UseIPv4", "UseIPv6", "UseSystem"}, Notes: []string{"Xray accepts documented spelling aliases case-insensitively."}},
	"NameServerConfig.queryStrategy":      {Values: []string{"UseIP", "UseIPv4", "UseIPv6", "UseSystem"}, Notes: []string{"Xray accepts documented spelling aliases case-insensitively."}},
	"DNSOutboundRuleConfig.action":        {Values: []string{"direct", "drop", "return", "hijack"}},
	"WireGuardConfig.domainStrategy":      {Values: []string{"", "forceip", "forceipv4", "forceipv6", "forceipv4v6", "forceipv6v4"}},
	"QuicParamsConfig.congestion":         {Values: []string{"", "brutal", "force-brutal", "reno", "bbr"}},
	"VLessOutboundConfig.flow":            {Values: []string{"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"}},
	"VMessAccount.security":               {Values: []string{"aes-128-gcm", "chacha20-poly1305", "auto", "none", "zero"}, Notes: []string{"Hop policy permits only auto, aes-128-gcm, and chacha20-poly1305."}},
	"VMessOutboundConfig.security":        {Values: []string{"aes-128-gcm", "chacha20-poly1305", "auto", "none", "zero"}, Notes: []string{"Hop policy permits only auto, aes-128-gcm, and chacha20-poly1305."}},
	"ShadowsocksClientConfig.method":      {Values: []string{"aes-128-gcm", "aead_aes_128_gcm", "aes-256-gcm", "aead_aes_256_gcm", "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305", "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "none", "plain"}, Notes: []string{"The enum records values parsed by the pinned core and pinned SS2022 dependency; Hop rejects none/plain and applies its reviewed secure allowlist."}},
	"ShadowsocksServerTarget.method":      {Values: []string{"aes-128-gcm", "aead_aes_128_gcm", "aes-256-gcm", "aead_aes_256_gcm", "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305", "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "none", "plain"}},
}

var applicabilityOverlays = map[string]string{
	"Config.transport":        "excluded-deprecated",
	"Config.log":              "hop-managed",
	"Config.routing":          "client-advanced",
	"Config.dns":              "client-advanced",
	"Config.inbounds":         "hop-managed-tun-only",
	"Config.outbounds":        "client",
	"Config.policy":           "client-advanced",
	"Config.api":              "excluded-server-only",
	"Config.metrics":          "excluded-server-only",
	"Config.stats":            "excluded-app-telemetry",
	"Config.reverse":          "excluded-server-only",
	"Config.fakeDns":          "client-advanced",
	"Config.observatory":      "client-advanced",
	"Config.burstObservatory": "client-advanced",
	"Config.version":          "client-advanced",
	"Config.geodata":          "client-advanced-local-assets-only",

	"OutboundDetourConfig.protocol":       "hop-typed",
	"OutboundDetourConfig.tag":            "hop-typed",
	"OutboundDetourConfig.settings":       "client-profile",
	"OutboundDetourConfig.streamSettings": "client-profile",
	"OutboundDetourConfig.proxySettings":  "client-profile",
	"OutboundDetourConfig.mux":            "client-profile",
	"VLessOutboundConfig.reverse":         "excluded-reverse-proxy",
	"Policy.statsUserDownlink":            "excluded-app-telemetry",
	"Policy.statsUserOnline":              "excluded-app-telemetry",
	"Policy.statsUserUplink":              "excluded-app-telemetry",
	"SystemPolicy.statsInboundDownlink":   "excluded-app-telemetry",
	"SystemPolicy.statsInboundUplink":     "excluded-app-telemetry",
	"SystemPolicy.statsOutboundDownlink":  "excluded-app-telemetry",
	"SystemPolicy.statsOutboundUplink":    "excluded-app-telemetry",
	"KCPConfig.header":                    "excluded-removed-feature",
	"KCPConfig.seed":                      "excluded-removed-feature",

	"StreamConfig.address":  "hop-typed",
	"StreamConfig.port":     "hop-typed",
	"StreamConfig.network":  "hop-typed",
	"StreamConfig.security": "hop-typed",

	"REALITYConfig.masterKeyLog":          "excluded-client-unsafe",
	"REALITYConfig.target":                "server-only",
	"REALITYConfig.dest":                  "server-only-legacy-alias",
	"REALITYConfig.type":                  "server-only",
	"REALITYConfig.xver":                  "server-only",
	"REALITYConfig.serverNames":           "server-only",
	"REALITYConfig.privateKey":            "server-only",
	"REALITYConfig.minClientVer":          "server-only",
	"REALITYConfig.maxClientVer":          "server-only",
	"REALITYConfig.maxTimeDiff":           "server-only",
	"REALITYConfig.shortIds":              "server-only",
	"REALITYConfig.mldsa65Seed":           "server-only",
	"REALITYConfig.limitFallbackUpload":   "server-only",
	"REALITYConfig.limitFallbackDownload": "server-only",
	"REALITYConfig.fingerprint":           "client",
	"REALITYConfig.serverName":            "client",
	"REALITYConfig.password":              "client",
	"REALITYConfig.publicKey":             "client-legacy-alias",
	"REALITYConfig.shortId":               "client",
	"REALITYConfig.mldsa65Verify":         "client",
	"REALITYConfig.spiderX":               "client",

	"TLSConfig.allowInsecure":       "excluded-removed-feature",
	"TLSConfig.rejectUnknownSni":    "server-only",
	"TLSConfig.echServerKeys":       "server-only",
	"TLSConfig.masterKeyLog":        "excluded-client-unsafe",
	"TLSCertConfig.keyFile":         "excluded-external-file",
	"TLSCertConfig.certificateFile": "excluded-external-file",

	"TCPConfig.acceptProxyProtocol":         "server-only",
	"WebSocketConfig.acceptProxyProtocol":   "server-only",
	"HttpUpgradeConfig.acceptProxyProtocol": "server-only",
	"Masquerade.dir":                        "server-only",
	"Masquerade.url":                        "server-only",
	"Masquerade.rewriteHost":                "server-only",
	"Masquerade.insecure":                   "server-only",
	"Masquerade.content":                    "server-only",
	"Masquerade.headers":                    "server-only",
	"Masquerade.statusCode":                 "server-only",
	"HysteriaConfig.masquerade":             "server-only",
	"RawFieldRule.webhook":                  "excluded-unsupported-network-probe",
	"RawFieldRule.process":                  "excluded-ios-unavailable",
	"GeodataAssetConfig.url":                "excluded-network-download",
	"GeodataAssetConfig.file":               "verified-local-only",
	"SocketConfig.customSockopt":            "excluded-ios-unsafe",
}

var annotationOverlays = map[string][]string{
	"MuxConfig.concurrency":                        {"memory-sensitive"},
	"MuxConfig.xudpConcurrency":                    {"memory-sensitive"},
	"SplitHTTPConfig.xPaddingBytes":                {"memory-sensitive"},
	"SplitHTTPConfig.uplinkChunkSize":              {"memory-sensitive"},
	"SplitHTTPConfig.scMaxEachPostBytes":           {"memory-sensitive"},
	"SplitHTTPConfig.scMaxBufferedPosts":           {"memory-sensitive"},
	"SplitHTTPConfig.xmux":                         {"memory-sensitive"},
	"XmuxConfig.maxConcurrency":                    {"memory-sensitive"},
	"XmuxConfig.maxConnections":                    {"memory-sensitive"},
	"GRPCConfig.initial_windows_size":              {"memory-sensitive"},
	"KCPConfig.mtu":                                {"memory-sensitive"},
	"KCPConfig.uplinkCapacity":                     {"memory-sensitive"},
	"KCPConfig.downlinkCapacity":                   {"memory-sensitive"},
	"KCPConfig.maxSendingWindow":                   {"memory-sensitive"},
	"QuicParamsConfig.initStreamReceiveWindow":     {"memory-sensitive"},
	"QuicParamsConfig.maxStreamReceiveWindow":      {"memory-sensitive"},
	"QuicParamsConfig.initConnectionReceiveWindow": {"memory-sensitive"},
	"QuicParamsConfig.maxConnectionReceiveWindow":  {"memory-sensitive"},
	"QuicParamsConfig.maxIncomingStreams":          {"memory-sensitive"},
	"FinalMask.tcp":                                {"memory-sensitive"},
	"FinalMask.udp":                                {"memory-sensitive"},
	"WireGuardConfig.peers":                        {"memory-sensitive"},
	"DNSConfig.servers":                            {"memory-sensitive"},
	"RouterConfig.rules":                           {"memory-sensitive"},
	"ObservatoryConfig.subjectSelector":            {"memory-sensitive"},
	"BurstObservatoryConfig.subjectSelector":       {"memory-sensitive"},
	"Policy.bufferSize":                            {"memory-sensitive"},
	"BalancingRule.selector":                       {"memory-sensitive"},
	"FakeDNSPoolElementConfig.poolSize":            {"memory-sensitive"},

	"VLessOutboundConfig.id":           {"secret", "security-critical"},
	"VLessOutboundConfig.seed":         {"secret", "security-critical"},
	"VLessOutboundConfig.encryption":   {"secret", "security-critical"},
	"VLessOutboundConfig.flow":         {"security-critical"},
	"VMessOutboundConfig.id":           {"secret", "security-critical"},
	"VMessAccount.id":                  {"secret", "security-critical"},
	"VMessOutboundConfig.security":     {"security-critical"},
	"TrojanClientConfig.password":      {"secret", "security-critical"},
	"TrojanServerTarget.password":      {"secret", "security-critical"},
	"ShadowsocksClientConfig.password": {"secret", "security-critical"},
	"ShadowsocksClientConfig.method":   {"security-critical"},
	"ShadowsocksServerTarget.password": {"secret", "security-critical"},
	"ShadowsocksUserConfig.password":   {"secret", "security-critical"},
	"SocksClientConfig.pass":           {"secret"},
	"SocksAccount.pass":                {"secret"},
	"HTTPClientConfig.pass":            {"secret"},
	"HTTPAccount.pass":                 {"secret"},
	"WireGuardConfig.secretKey":        {"secret", "security-critical"},
	"WireGuardPeerConfig.preSharedKey": {"secret", "security-critical"},
	"HysteriaConfig.auth":              {"secret", "security-critical"},
	"TLSCertConfig.key":                {"secret"},
	"TLSCertConfig.keyFile":            {"secret"},
	"TLSConfig.serverName":             {"security-critical"},
	"TLSConfig.minVersion":             {"security-critical"},
	"TLSConfig.maxVersion":             {"security-critical"},
	"TLSConfig.cipherSuites":           {"security-critical"},
	"TLSConfig.fingerprint":            {"security-critical"},
	"TLSConfig.curvePreferences":       {"security-critical"},
	"TLSConfig.pinnedPeerCertSha256":   {"security-critical"},
	"TLSConfig.verifyPeerCertByName":   {"security-critical"},
	"TLSConfig.echConfigList":          {"security-critical"},
	"TLSConfig.echServerKeys":          {"secret", "security-critical"},
	"TLSConfig.allowInsecure":          {"security-critical"},
	"TLSConfig.disableSystemRoot":      {"security-critical"},
	"REALITYConfig.password":           {"security-critical"},
	"REALITYConfig.publicKey":          {"security-critical"},
	"REALITYConfig.serverName":         {"security-critical"},
	"REALITYConfig.fingerprint":        {"security-critical"},
	"REALITYConfig.shortId":            {"security-critical"},
	"REALITYConfig.mldsa65Verify":      {"security-critical"},
	"REALITYConfig.privateKey":         {"secret", "security-critical"},
	"REALITYConfig.mldsa65Seed":        {"secret", "security-critical"},
	"Salamander.password":              {"secret", "security-critical"},
	"Sudoku.password":                  {"secret", "security-critical"},
	"Realm.url":                        {"secret"},
}

func main() {
	var source string
	flag.StringVar(&source, "xray-source", "", "path to the pinned github.com/xtls/xray-core module source")
	flag.Parse()
	if source == "" {
		fatalf("-xray-source is required")
	}

	types, err := parseConfigTypes(filepath.Join(source, "infra", "conf"))
	if err != nil {
		fatalf("parse pinned Xray config structs: %v", err)
	}
	for _, name := range seedTypes {
		if _, ok := types[name]; !ok {
			fatalf("pinned Xray source no longer defines required config struct %q", name)
		}
	}

	definitions := buildDefinitions(types)
	m := buildManifest(definitions)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fatalf("encode manifest: %v", err)
	}
	data = append(data, '\n')
	if _, err := os.Stdout.Write(data); err != nil {
		fatalf("write manifest: %v", err)
	}
}

func parseConfigTypes(dir string) (map[string]parsedType, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fileSet := token.NewFileSet()
	result := make(map[string]parsedType)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return nil, err
		}
		if file.Name.Name != "conf" {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			typeSpec, ok := node.(*ast.TypeSpec)
			if !ok {
				return true
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				return true
			}
			position := fileSet.Position(typeSpec.Pos())
			result[typeSpec.Name.Name] = parsedType{
				Name:       typeSpec.Name.Name,
				Struct:     structType,
				SourceFile: filepath.ToSlash(filepath.Join("infra", "conf", entry.Name())),
				Line:       position.Line,
			}
			return true
		})
	}
	return result, nil
}

func buildDefinitions(types map[string]parsedType) map[string]definition {
	selected := make(map[string]bool)
	queue := append([]string(nil), seedTypes...)
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if selected[name] {
			continue
		}
		selected[name] = true
		parsed, ok := types[name]
		if !ok {
			continue
		}
		for _, ref := range referencedTypes(parsed.Struct) {
			if types[ref].Struct != nil && !selected[ref] && !skipReferencedType(name, ref) && !inlineCustomType(ref) {
				queue = append(queue, ref)
			}
		}
	}

	result := make(map[string]definition, len(selected))
	for name := range selected {
		parsed, ok := types[name]
		if !ok {
			continue
		}
		result[name] = definitionFromAST(parsed, types)
	}
	applyCustomShapes(result, types)
	return result
}

func skipReferencedType(parent, child string) bool {
	if parent != "Config" {
		return false
	}
	switch child {
	case "InboundDetourConfig", "APIConfig", "MetricsConfig", "ReverseConfig":
		return true
	default:
		return false
	}
}

func inlineCustomType(name string) bool {
	switch name {
	case "Address", "HostsWrapper", "HostAddress", "Int32Range", "NetworkList", "PortList", "PortRange", "StringList":
		return true
	default:
		return false
	}
}

func referencedTypes(structType *ast.StructType) []string {
	seen := make(map[string]bool)
	var inspect func(ast.Expr)
	inspect = func(expr ast.Expr) {
		switch value := expr.(type) {
		case *ast.Ident:
			seen[value.Name] = true
		case *ast.StarExpr:
			inspect(value.X)
		case *ast.ArrayType:
			inspect(value.Elt)
		case *ast.MapType:
			inspect(value.Value)
		}
	}
	for _, field := range structType.Fields.List {
		inspect(field.Type)
	}
	values := make([]string, 0, len(seen))
	for name := range seen {
		values = append(values, name)
	}
	sort.Strings(values)
	return values
}

func definitionFromAST(parsed parsedType, allTypes map[string]parsedType) definition {
	result := definition{
		JSONTypes:     []string{"object"},
		Applicability: definitionApplicability(parsed.Name),
		Source:        sourceLocation{File: parsed.SourceFile, Line: parsed.Line},
		Fields:        make(map[string]fieldSchema),
	}
	for _, field := range parsed.Struct.Fields.List {
		if len(field.Names) == 0 {
			if ident := baseIdent(field.Type); ident != "" && allTypes[ident].Struct != nil {
				result.Inherits = append(result.Inherits, ref(ident))
			}
			continue
		}
		jsonName, options, explicitlyEmpty, skip := jsonFieldName(field)
		if skip {
			continue
		}
		for _, name := range field.Names {
			fieldName := jsonName
			if fieldName == "" {
				if explicitlyEmpty {
					// Internal discriminator fields such as WireGuardConfig.IsClient
					// deliberately have json:"" and are not part of Hop's schema.
					continue
				}
				fieldName = name.Name
			}
			use, optional := typeUseFromExpr(field.Type, allTypes)
			key := parsed.Name + "." + fieldName
			item := fieldSchema{
				GoField:       name.Name,
				JSONTypes:     use.JSONTypes,
				Ref:           use.Ref,
				Items:         use.Items,
				Optional:      optional || options["omitempty"],
				Applicability: applicability(parsed.Name, fieldName),
				Annotations:   sortedCopy(annotationOverlays[key]),
			}
			if stripsReference(key) {
				item.Ref = ""
				stripTypeUseRefs(item.Items)
				stripTypeUseRefs(item.Additional)
			}
			if overlay, ok := enumOverlays[key]; ok {
				item.Enum = append([]string(nil), overlay.Values...)
				item.Notes = append([]string(nil), overlay.Notes...)
			}
			if len(item.JSONTypes) == 1 && item.JSONTypes[0] == "object" && strings.HasPrefix(use.GoType, "map[") {
				item.Additional = use.Items
				item.Items = nil
			}
			result.Fields[fieldName] = item
		}
	}
	sort.Strings(result.Inherits)
	return result
}

func stripsReference(key string) bool {
	switch key {
	case "Config.transport", "Config.inbounds", "Config.api", "Config.metrics", "Config.reverse":
		return true
	default:
		return false
	}
}

func stripTypeUseRefs(use *typeUse) {
	if use == nil {
		return
	}
	use.Ref = ""
	stripTypeUseRefs(use.Items)
}

func jsonFieldName(field *ast.Field) (string, map[string]bool, bool, bool) {
	options := make(map[string]bool)
	if field.Tag == nil {
		return "", options, false, false
	}
	literal, err := strconv.Unquote(field.Tag.Value)
	if err != nil {
		return "", options, false, false
	}
	tag := reflectStructTag(literal, "json")
	if tag == "-" {
		return "", options, false, true
	}
	parts := strings.Split(tag, ",")
	for _, option := range parts[1:] {
		options[option] = true
	}
	return parts[0], options, tag == "", false
}

// reflectStructTag is the small subset of reflect.StructTag.Get needed by the
// generator, kept local so generation depends only on parsed pinned source.
func reflectStructTag(tag, key string) string {
	for tag != "" {
		tag = strings.TrimLeft(tag, " ")
		if tag == "" {
			break
		}
		index := strings.IndexByte(tag, ':')
		if index <= 0 {
			break
		}
		name := tag[:index]
		tag = tag[index+1:]
		if tag == "" || tag[0] != '"' {
			break
		}
		value, err := strconv.QuotedPrefix(tag)
		if err != nil {
			break
		}
		tag = tag[len(value):]
		if name == key {
			unquoted, _ := strconv.Unquote(value)
			return unquoted
		}
	}
	return ""
}

func typeUseFromExpr(expr ast.Expr, allTypes map[string]parsedType) (typeUse, bool) {
	switch value := expr.(type) {
	case *ast.StarExpr:
		use, _ := typeUseFromExpr(value.X, allTypes)
		return use, true
	case *ast.ArrayType:
		item, _ := typeUseFromExpr(value.Elt, allTypes)
		if ident, ok := value.Elt.(*ast.Ident); ok && ident.Name == "byte" {
			return typeUse{JSONTypes: []string{"array", "string"}, GoType: "[]byte", Items: &typeUse{JSONTypes: []string{"integer"}, GoType: "byte"}}, false
		}
		return typeUse{JSONTypes: []string{"array"}, GoType: exprString(expr), Items: &item}, false
	case *ast.MapType:
		item, _ := typeUseFromExpr(value.Value, allTypes)
		return typeUse{JSONTypes: []string{"object"}, GoType: exprString(expr), Items: &item}, false
	case *ast.InterfaceType:
		return typeUse{JSONTypes: []string{"any"}, GoType: "interface{}"}, false
	case *ast.SelectorExpr:
		name := exprString(expr)
		switch name {
		case "json.RawMessage":
			return typeUse{JSONTypes: []string{"any"}, GoType: name}, false
		case "duration.Duration":
			return typeUse{JSONTypes: []string{"string"}, GoType: name}, false
		default:
			return typeUse{JSONTypes: []string{"object"}, GoType: name}, false
		}
	case *ast.Ident:
		return typeUseForIdent(value.Name, allTypes), false
	default:
		return typeUse{JSONTypes: []string{"any"}, GoType: exprString(expr)}, false
	}
}

func typeUseForIdent(name string, allTypes map[string]parsedType) typeUse {
	switch name {
	case "string":
		return typeUse{JSONTypes: []string{"string"}, GoType: name}
	case "bool":
		return typeUse{JSONTypes: []string{"boolean"}, GoType: name}
	case "byte", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64":
		return typeUse{JSONTypes: []string{"integer"}, GoType: name}
	case "float32", "float64":
		return typeUse{JSONTypes: []string{"number"}, GoType: name}
	case "Address", "Network", "TransportProtocol", "Bandwidth":
		return typeUse{JSONTypes: []string{"string"}, GoType: name}
	case "StringList", "NetworkList":
		return typeUse{JSONTypes: []string{"array", "string"}, GoType: name, Items: &typeUse{JSONTypes: []string{"string"}, GoType: "string"}}
	case "PortList":
		return typeUse{JSONTypes: []string{"integer", "string"}, GoType: name}
	case "Int32Range":
		return typeUse{JSONTypes: []string{"integer", "string"}, GoType: name}
	case "HostsWrapper":
		return typeUse{JSONTypes: []string{"object"}, GoType: name, Items: &typeUse{JSONTypes: []string{"array", "string"}}}
	case "FakeDNSConfig":
		return typeUse{JSONTypes: []string{"array", "object"}, Ref: ref(name), GoType: name}
	}
	if _, ok := allTypes[name]; ok {
		return typeUse{JSONTypes: []string{"object"}, Ref: ref(name), GoType: name}
	}
	return typeUse{JSONTypes: []string{"any"}, GoType: name}
}

func baseIdent(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return baseIdent(value.X)
	default:
		return ""
	}
}

func exprString(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return exprString(value.X) + "." + value.Sel.Name
	case *ast.StarExpr:
		return "*" + exprString(value.X)
	case *ast.ArrayType:
		return "[]" + exprString(value.Elt)
	case *ast.MapType:
		return "map[" + exprString(value.Key) + "]" + exprString(value.Value)
	default:
		return fmt.Sprintf("%T", expr)
	}
}

func applyCustomShapes(definitions map[string]definition, types map[string]parsedType) {
	if item, ok := definitions["NameServerConfig"]; ok {
		item.JSONTypes = []string{"object", "string"}
		item.Notes = append(item.Notes, "NameServerConfig.UnmarshalJSON accepts either an address string or the expanded object fields.")
		definitions["NameServerConfig"] = item
	}
	if parsed, ok := types["FakeDNSConfig"]; ok {
		definitions["FakeDNSConfig"] = definition{
			JSONTypes:     []string{"array", "object"},
			Applicability: "client",
			Source:        sourceLocation{File: parsed.SourceFile, Line: parsed.Line},
			OneOf: []typeUse{
				{JSONTypes: []string{"object"}, Ref: ref("FakeDNSPoolElementConfig")},
				{JSONTypes: []string{"array"}, Items: &typeUse{JSONTypes: []string{"object"}, Ref: ref("FakeDNSPoolElementConfig")}},
			},
			Notes: []string{"Shape is defined by FakeDNSConfig.UnmarshalJSON rather than exported struct fields."},
		}
	}
	if parsed, ok := types["RawFieldRule"]; ok {
		item := definitions["RawFieldRule"]
		item.Source = sourceLocation{File: parsed.SourceFile, Line: parsed.Line}
		item.Notes = []string{"Function-local struct used by parseFieldRule; inherited RouterRule fields are valid JSON fields."}
		definitions["RawFieldRule"] = item
	}
	// RawMessage protocol users are typed dynamically. These definitions make
	// the common account shapes explicit without pretending RawMessage is closed.
	for name, note := range map[string]string{
		"VLessOutboundVnext":  "users entries are Xray VLESS account JSON; Hop accepts the flat client fields and preserves reviewed long-tail settings.",
		"VMessOutboundTarget": "users entries use VMessAccount fields.",
		"SocksRemoteConfig":   "users entries use SocksAccount fields.",
		"HTTPRemoteConfig":    "users entries use HTTPAccount fields.",
	} {
		item := definitions[name]
		item.Notes = append(item.Notes, note)
		definitions[name] = item
	}
}

func buildManifest(definitions map[string]definition) manifest {
	return manifest{
		FormatVersion: formatVersion,
		Generator: generatorInfo{
			Command: "scripts/generate-xray-client-schema.sh",
			Method:  "Go AST over JSON-tagged structs plus reviewed RawMessage unions and policy overlays",
		},
		Core: coreInfo{
			Version:       coreVersion,
			Commit:        coreCommit,
			Module:        "github.com/xtls/xray-core",
			ModuleVersion: coreModuleVersion,
			SourcePackage: "github.com/xtls/xray-core/infra/conf",
		},
		Scope: scopeInfo{
			Applicability: "Hop client runtime on iOS",
			Includes: []string{
				"client outbounds and account settings registered by LibXray",
				"RAW, WebSocket, gRPC, HTTPUpgrade, XHTTP, mKCP, and Hysteria transports",
				"TLS, REALITY, FinalMask, mux, socket options, DNS, FakeDNS, routing, policy, balancing, observatory, version, and local geodata",
			},
			Excludes: []string{
				"custom server inbounds (the TUN inbound is generated and owned by Hop)",
				"API and metrics listeners, reverse proxy, server-only transport/security fields",
				"deprecated global transport settings and upstream removed features",
			},
		},
		Roots: map[string]section{
			"config":           {Ref: ref("Config"), Applicability: "client"},
			"outbound":         {Ref: ref("OutboundDetourConfig"), Applicability: "client"},
			"streamSettings":   {Ref: ref("StreamConfig"), Applicability: "client"},
			"dns":              {Ref: ref("DNSConfig"), Applicability: "client"},
			"fakeDns":          {Ref: ref("FakeDNSConfig"), Applicability: "client"},
			"routing":          {Ref: ref("RouterConfig"), Applicability: "client"},
			"routingFieldRule": {Ref: ref("RawFieldRule"), Applicability: "client"},
			"policy":           {Ref: ref("PolicyConfig"), Applicability: "client"},
			"observatory":      {Ref: ref("ObservatoryConfig"), Applicability: "client"},
			"burstObservatory": {Ref: ref("BurstObservatoryConfig"), Applicability: "client"},
			"version":          {Ref: ref("VersionConfig"), Applicability: "client"},
			"geodata":          {Ref: ref("GeodataConfig"), Applicability: "client-local-assets-only"},
		},
		Protocols: map[string]protocolSection{
			"blackhole":   {Ref: ref("BlackholeConfig"), Applicability: "outbound-client", Aliases: []string{"block"}},
			"dns":         {Ref: ref("DNSOutboundConfig"), Applicability: "outbound-client"},
			"freedom":     {Ref: ref("FreedomConfig"), Applicability: "outbound-client", Aliases: []string{"direct"}},
			"http":        {Ref: ref("HTTPClientConfig"), Applicability: "outbound-client"},
			"hysteria":    {Ref: ref("HysteriaClientConfig"), Applicability: "outbound-client", Notes: []string{"Authentication and QUIC controls are in streamSettings.hysteriaSettings."}},
			"loopback":    {Ref: ref("LoopbackConfig"), Applicability: "outbound-client-hop-internal"},
			"shadowsocks": {Ref: ref("ShadowsocksClientConfig"), Applicability: "outbound-client", Notes: []string{"Includes Xray's registered Shadowsocks and SS2022 client config shape; Hop enforces the pinned secure cipher allowlist."}},
			"socks":       {Ref: ref("SocksClientConfig"), Applicability: "outbound-client"},
			"trojan":      {Ref: ref("TrojanClientConfig"), Applicability: "outbound-client"},
			"vless":       {Ref: ref("VLessOutboundConfig"), Applicability: "outbound-client", Notes: []string{"encryption is preserved as the pinned VLESS Encryption/Auth grammar, including mlkem768x25519plus."}},
			"vmess":       {Ref: ref("VMessOutboundConfig"), Applicability: "outbound-client"},
			"wireguard":   {Ref: ref("WireGuardConfig"), Applicability: "outbound-client", Notes: []string{"Hop forces noKernelTun=true."}},
		},
		Transports: map[string]transportSection{
			"raw":         {SettingsField: "rawSettings", Ref: ref("TCPConfig"), Applicability: "client", Aliases: []string{"tcp"}},
			"websocket":   {SettingsField: "wsSettings", Ref: ref("WebSocketConfig"), Applicability: "client", Aliases: []string{"ws"}},
			"grpc":        {SettingsField: "grpcSettings", Ref: ref("GRPCConfig"), Applicability: "client"},
			"httpupgrade": {SettingsField: "httpupgradeSettings", Ref: ref("HttpUpgradeConfig"), Applicability: "client"},
			"xhttp":       {SettingsField: "xhttpSettings", Ref: ref("SplitHTTPConfig"), Applicability: "client", Aliases: []string{"splithttp"}},
			"mkcp":        {SettingsField: "kcpSettings", Ref: ref("KCPConfig"), Applicability: "client", Aliases: []string{"kcp"}},
			"hysteria":    {SettingsField: "hysteriaSettings", Ref: ref("HysteriaConfig"), Applicability: "client"},
			"tls":         {SettingsField: "tlsSettings", Ref: ref("TLSConfig"), Applicability: "client-and-server-shared-struct"},
			"reality":     {SettingsField: "realitySettings", Ref: ref("REALITYConfig"), Applicability: "client-and-server-shared-struct"},
		},
		FinalMask: finalMaskSection{
			Ref: ref("FinalMask"),
			TCP: map[string]finalMaskTypeSpec{
				"header-custom": {Ref: ref("HeaderCustomTCP"), Applicability: "client"},
				"fragment":      {Ref: ref("FragmentMask"), Applicability: "client"},
				"sudoku":        {Ref: ref("Sudoku"), Applicability: "client"},
			},
			UDP: map[string]finalMaskTypeSpec{
				"header-custom": {Ref: ref("HeaderCustomUDP"), Applicability: "client"},
				"mkcp-legacy":   {Ref: ref("MkcpLegacy"), Applicability: "client"},
				"noise":         {Ref: ref("NoiseMask"), Applicability: "client"},
				"salamander":    {Ref: ref("Salamander"), Applicability: "client"},
				"sudoku":        {Ref: ref("Sudoku"), Applicability: "client"},
				"xdns":          {Ref: ref("Xdns"), Applicability: "client"},
				"xicmp":         {Ref: ref("Xicmp"), Applicability: "client"},
				"realm":         {Ref: ref("Realm"), Applicability: "client"},
			},
		},
		DynamicShapes: map[string]dynamicShape{
			"blackholeResponse": {
				Location:      "/outbounds/*/settings/response",
				Discriminator: "type",
				Variants: map[string]dynamicValue{
					"none": {Ref: ref("NoneResponse"), Applicability: "client"},
					"http": {Ref: ref("HTTPResponse"), Applicability: "client"},
				},
			},
			"rawHeader": {
				Location:      "/outbounds/*/streamSettings/rawSettings/header",
				Discriminator: "type",
				Variants: map[string]dynamicValue{
					"none": {Ref: ref("NoOpConnectionAuthenticator"), Applicability: "client"},
					"http": {Ref: ref("Authenticator"), Applicability: "client"},
				},
			},
			"routingRule": {
				Location: "/routing/rules/*",
				Ref:      ref("RawFieldRule"),
				Notes:    []string{"Routing rules are RawMessage entries parsed as field rules; inherited RouterRule target fields also apply."},
			},
			"balancerStrategySettings": {
				Location:      "/routing/balancers/*/strategy/settings",
				Discriminator: "../type",
				Variants: map[string]dynamicValue{
					"random":     {Ref: ref("strategyEmptyConfig"), Applicability: "client"},
					"leastping":  {Ref: ref("strategyEmptyConfig"), Applicability: "client"},
					"roundrobin": {Ref: ref("strategyEmptyConfig"), Applicability: "client"},
					"leastload":  {Ref: ref("strategyLeastLoadConfig"), Applicability: "client"},
				},
			},
			"xhttpExtra": {
				Location: "/outbounds/*/streamSettings/xhttpSettings/extra",
				Ref:      ref("SplitHTTPConfig"),
				Notes:    []string{"extra is reparsed as SplitHTTPConfig; outer host, path, and mode remain authoritative."},
			},
			"vmessUser": {
				Location: "/outbounds/*/settings/vnext/*/users/*",
				Ref:      ref("VMessAccount"),
			},
			"socksUser": {
				Location: "/outbounds/*/settings/servers/*/users/*",
				Ref:      ref("SocksAccount"),
				Notes:    []string{"Applies when the parent outbound protocol is socks."},
			},
			"httpUser": {
				Location: "/outbounds/*/settings/servers/*/users/*",
				Ref:      ref("HTTPAccount"),
				Notes:    []string{"Applies when the parent outbound protocol is http."},
			},
		},
		Definitions: definitions,
		Annotations: buildAnnotations(),
	}
}

func buildAnnotations() annotations {
	secret := make([]string, 0)
	security := make([]string, 0)
	memory := make([]string, 0)
	for key, values := range annotationOverlays {
		path := canonicalPath(key)
		for _, value := range values {
			switch value {
			case "secret":
				secret = append(secret, path)
			case "security-critical":
				security = append(security, path)
			case "memory-sensitive":
				memory = append(memory, path)
			}
		}
	}
	sort.Strings(secret)
	sort.Strings(security)
	sort.Strings(memory)
	hopManaged := []string{
		"/inbounds", "/log", "/outbounds/*/protocol", "/outbounds/*/tag",
		"/outbounds/*/streamSettings/address", "/outbounds/*/streamSettings/network",
		"/outbounds/*/streamSettings/port", "/outbounds/*/streamSettings/security",
	}
	sort.Strings(hopManaged)
	rejected := []rejectedPath{
		{Path: "/api", Reason: "API listeners are outside Hop's client schema."},
		{Path: "/inbounds", Reason: "Arbitrary listeners are forbidden; Hop generates exactly one TUN inbound."},
		{Path: "/log/access", Reason: "The core may not write arbitrary files; extension logging is bounded and sanitized."},
		{Path: "/log/error", Reason: "The core may not write arbitrary files; extension logging is bounded and sanitized."},
		{Path: "/metrics", Reason: "Metrics listeners are outside Hop's client schema."},
		{Path: "/reverse", Reason: "Reverse proxy is outside Hop's client schema."},
		{Path: "/stats", Reason: "Runtime traffic telemetry is not part of Hop's client schema."},
		{Path: "/policy/levels/*/statsUserDownlink", Reason: "Runtime traffic telemetry is not part of Hop's client schema."},
		{Path: "/policy/levels/*/statsUserOnline", Reason: "Runtime traffic telemetry is not part of Hop's client schema."},
		{Path: "/policy/levels/*/statsUserUplink", Reason: "Runtime traffic telemetry is not part of Hop's client schema."},
		{Path: "/policy/system", Reason: "Xray system policy contains only runtime traffic telemetry flags, which Hop does not expose."},
		{Path: "/transport", Reason: "Deprecated global transport configuration is rejected by the pinned core."},
		{Path: "/geodata/assets/*/url", Reason: "Hop permits only verified local geodata; runtime asset downloads are forbidden."},
		{Path: "/geodata/assets/*/file", Reason: "Asset paths must resolve to a Hop-verified local asset."},
		{Path: "/routing/rules/*/webhook", Reason: "Unsupported network probes and callbacks are forbidden."},
		{Path: "/routing/rules/*/process", Reason: "Per-process routing cannot be reproduced by Hop's iOS packet tunnel."},
		{Path: "/outbounds/*/streamSettings/sockopt/customSockopt", Reason: "Arbitrary platform socket options are unsafe and unavailable on iOS."},
		{Path: "/outbounds/*/streamSettings/tlsSettings/allowInsecure", Reason: "Removed by Xray v26.6.27 and forbidden by Hop policy."},
		{Path: "/outbounds/*/streamSettings/tlsSettings/masterKeyLog", Reason: "TLS master-key logging is forbidden."},
		{Path: "/outbounds/*/streamSettings/tlsSettings/certificates/*/certificateFile", Reason: "Unverified external file reads are forbidden."},
		{Path: "/outbounds/*/streamSettings/tlsSettings/certificates/*/keyFile", Reason: "Unverified external file reads and key files are forbidden."},
		{Path: "/outbounds/*/streamSettings/realitySettings/masterKeyLog", Reason: "REALITY master-key logging is forbidden."},
		{Path: "/outbounds/*/streamSettings/realitySettings/privateKey", Reason: "Server-only REALITY fields are forbidden."},
		{Path: "/outbounds/*/streamSettings/hysteriaSettings/masquerade", Reason: "Hysteria server masquerade settings are outside client schema."},
		{Path: "/outbounds/*/streamSettings/kcpSettings/header", Reason: "The pinned core removed legacy mKCP headers; use FinalMask instead."},
		{Path: "/outbounds/*/streamSettings/kcpSettings/seed", Reason: "The pinned core removed legacy mKCP seed obfuscation; use FinalMask instead."},
		{Path: "/outbounds/*/settings/reverse", Reason: "VLESS reverse proxy is outside Hop's client schema."},
	}
	sort.Slice(rejected, func(i, j int) bool { return rejected[i].Path < rejected[j].Path })
	return annotations{
		SecretPaths:           unique(secret),
		SecurityCriticalPaths: unique(security),
		MemorySensitivePaths:  unique(memory),
		HopManagedPaths:       hopManaged,
		RejectedPaths:         rejected,
	}
}

func canonicalPath(key string) string {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) != 2 {
		return key
	}
	prefix := map[string]string{
		"OutboundDetourConfig":     "/outbounds/*",
		"MuxConfig":                "/outbounds/*/mux",
		"VLessOutboundConfig":      "/outbounds/*/settings",
		"VMessOutboundConfig":      "/outbounds/*/settings",
		"VMessAccount":             "/outbounds/*/settings/vnext/*/users/*",
		"TrojanClientConfig":       "/outbounds/*/settings",
		"TrojanServerTarget":       "/outbounds/*/settings/servers/*",
		"ShadowsocksClientConfig":  "/outbounds/*/settings",
		"ShadowsocksServerTarget":  "/outbounds/*/settings/servers/*",
		"ShadowsocksUserConfig":    "/outbounds/*/settings/servers/*/users/*",
		"SocksClientConfig":        "/outbounds/*/settings",
		"SocksAccount":             "/outbounds/*/settings/servers/*/users/*",
		"HTTPClientConfig":         "/outbounds/*/settings",
		"HTTPAccount":              "/outbounds/*/settings/servers/*/users/*",
		"WireGuardConfig":          "/outbounds/*/settings",
		"WireGuardPeerConfig":      "/outbounds/*/settings/peers/*",
		"StreamConfig":             "/outbounds/*/streamSettings",
		"SplitHTTPConfig":          "/outbounds/*/streamSettings/xhttpSettings",
		"XmuxConfig":               "/outbounds/*/streamSettings/xhttpSettings/xmux",
		"GRPCConfig":               "/outbounds/*/streamSettings/grpcSettings",
		"KCPConfig":                "/outbounds/*/streamSettings/kcpSettings",
		"HysteriaConfig":           "/outbounds/*/streamSettings/hysteriaSettings",
		"TLSConfig":                "/outbounds/*/streamSettings/tlsSettings",
		"TLSCertConfig":            "/outbounds/*/streamSettings/tlsSettings/certificates/*",
		"REALITYConfig":            "/outbounds/*/streamSettings/realitySettings",
		"QuicParamsConfig":         "/outbounds/*/streamSettings/finalmask/quicParams",
		"FinalMask":                "/outbounds/*/streamSettings/finalmask",
		"Salamander":               "/outbounds/*/streamSettings/finalmask/*/*/settings",
		"Sudoku":                   "/outbounds/*/streamSettings/finalmask/*/*/settings",
		"Realm":                    "/outbounds/*/streamSettings/finalmask/udp/*/settings",
		"DNSConfig":                "/dns",
		"RouterConfig":             "/routing",
		"BalancingRule":            "/routing/balancers/*",
		"FakeDNSPoolElementConfig": "/fakeDns/*",
		"Policy":                   "/policy/levels/*",
		"SystemPolicy":             "/policy/system",
		"ObservatoryConfig":        "/observatory",
		"BurstObservatoryConfig":   "/burstObservatory",
	}[parts[0]]
	if prefix == "" {
		return "/" + parts[0] + "/" + parts[1]
	}
	return prefix + "/" + parts[1]
}

func definitionApplicability(name string) string {
	switch name {
	case "TLSConfig", "TLSCertConfig", "REALITYConfig", "StreamConfig", "TCPConfig", "WebSocketConfig", "HttpUpgradeConfig", "Masquerade":
		return "client-and-server-shared-struct"
	default:
		return "client"
	}
}

func applicability(typeName, fieldName string) string {
	if value := applicabilityOverlays[typeName+"."+fieldName]; value != "" {
		return value
	}
	return definitionApplicability(typeName)
}

func ref(name string) string { return "#/definitions/" + name }

func sortedCopy(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func unique(values []string) []string {
	if len(values) == 0 {
		return values
	}
	result := values[:0]
	for index, value := range values {
		if index == 0 || value != values[index-1] {
			result = append(result, value)
		}
	}
	return result
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "schema-manifest: "+format+"\n", args...)
	os.Exit(1)
}
