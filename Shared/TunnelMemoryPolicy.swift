import Dispatch

/// Pure memory-budget decisions shared by the packet tunnel and its tests.
/// Values leave enough headroom for an orderly LibXray shutdown below iOS's
/// approximately 50 MiB Network Extension ceiling.
enum TunnelMemoryPolicy {
    static let maximumConfigurationBytes = 512 * 1024
    static let watchdogSampleMilliseconds = 250
    static let softLimitBytes: UInt64 = 42 * 1024 * 1024
    static let hardLimitBytes: UInt64 = 46 * 1024 * 1024
    static let softResetBytes: UInt64 = 40 * 1024 * 1024

    enum Action: Equatable, Sendable {
        case none
        case collectAndWarn
        case stop
    }

    struct Decision: Equatable, Sendable {
        let action: Action
        let softWarningActive: Bool
    }

    static func decision(footprintBytes: UInt64, softWarningActive: Bool) -> Decision {
        if footprintBytes >= hardLimitBytes {
            return Decision(action: .stop, softWarningActive: true)
        }
        if footprintBytes >= softLimitBytes {
            return Decision(
                action: softWarningActive ? .none : .collectAndWarn,
                softWarningActive: true,
            )
        }
        if footprintBytes < softResetBytes {
            return Decision(action: .none, softWarningActive: false)
        }
        return Decision(action: .none, softWarningActive: softWarningActive)
    }
}

/// Serializes the watchdog's hard stop and NetworkExtension lifecycle callbacks.
/// Both can release the same borrowed utun and must finish in order.
final class TunnelServiceQueue: Sendable {
    private let queue = DispatchQueue(
        label: "cat.string.hop.tunnel-service",
        qos: .userInitiated,
        autoreleaseFrequency: .workItem,
    )

    func async(_ operation: @escaping @Sendable () -> Void) {
        queue.async(execute: operation)
    }

    func makeMemoryWatchdog(_ sample: @escaping @Sendable () -> Void) -> DispatchSourceTimer {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        let interval = DispatchTimeInterval.milliseconds(TunnelMemoryPolicy.watchdogSampleMilliseconds)
        timer.schedule(deadline: .now() + interval, repeating: interval, leeway: .milliseconds(50))
        timer.setEventHandler(handler: sample)
        return timer
    }
}
