#if DEBUG
    enum SampleData {
        static let vlessReality = ProxyProfile(
            name: "VLESS REALITY - Tokyo",
            endpoint: Endpoint(host: "edge.example.net", port: 443),
            options: .vless(VLESSOptions(uuid: "11111111-1111-4111-8111-111111111111", flow: "xtls-rprx-vision")),
            security: .reality(
                RealityOptions(
                    publicKey: "qwertyuiopasdfghjklzxcvbnm1234567890ABCDE",
                    shortID: "6ba85179e30d4fc2",
                    serverName: "www.cloudflare.com",
                    spiderX: "/",
                ),
            ),
        )

        static let trojanTLS = ProxyProfile(
            name: "Trojan TLS - Frankfurt",
            endpoint: Endpoint(host: "de.example.net", port: 443),
            options: .trojan(TrojanOptions(password: "replace-me")),
            security: .tls(TLSOptions(serverName: "de.example.net", alpn: ["h2", "http/1.1"])),
        )

        static let hysteria2 = ProxyProfile(
            name: "Hysteria2 TLS - NYC",
            endpoint: Endpoint(host: "nyc.example.net", port: 443),
            options: .hysteria2(Hysteria2Options(password: "replace-me", obfs: "salamander", obfsPassword: "obfs-secret")),
            security: .tls(TLSOptions(serverName: "nyc.example.net", alpn: ["h3"])),
        )

        static let profiles = [vlessReality, trojanTLS, hysteria2]

        static let autoGroup = ProxyGroup(
            name: "Auto",
            type: .urlTest,
            members: profiles.map { .profile($0.id) },
            defaultTarget: .profile(vlessReality.id),
            testOptions: ProxyGroupTestOptions(intervalSeconds: 600, toleranceMilliseconds: 50),
            lastLatencyMilliseconds: 42,
        )

        static let proxyGroup = ProxyGroup(
            name: "Proxy",
            type: .select,
            members: [
                .group(autoGroup.id),
                .profile(vlessReality.id),
                .profile(trojanTLS.id),
                .profile(hysteria2.id),
            ],
            defaultTarget: .group(autoGroup.id),
        )

        static let groups = [proxyGroup, autoGroup]

        static let subscriptions = [
            SubscriptionSource(
                name: "Example Subscription",
                url: "https://example.com/subscription",
                lastImportSummary: "3 nodes, 2 groups",
            ),
        ]

        static let rules = [
            RoutingRule(kind: .geoIP, value: "private", target: .direct),
        ] + RuleConfiguration.appleSystemBypassRules + [
            RoutingRule(kind: .domainSuffix, value: "youtube.com", target: .group(proxyGroup.id)),
        ]

        static let defaultConfiguration = RuleConfiguration(name: "Default", rules: rules)

        static let ruleConfigurations = [
            defaultConfiguration,
            RuleConfiguration.china(),
            RuleConfiguration.iran(),
        ]

        static let logs = [
            "[9:18:31 PM] Ready. Select an outbound, then tap Connect.",
            "[9:18:30 PM] NetworkExtension manager ready.",
            "[9:18:29 PM] App Group storage resolved.",
            "[9:18:28 PM] Tunnel extension bundle ID resolved.",
            "[9:18:27 PM] Loaded 3 sample nodes and 2 proxy groups.",
            "[9:18:26 PM] Routing mode set to Rule with 4 sample rules.",
            "[9:18:25 PM] Import parser ready for links, subscriptions, and compatible .conf files.",
            "[9:18:24 PM] Xray-core configuration builder ready.",
        ]
    }
#endif
