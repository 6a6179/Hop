import Foundation

/// Runs an async operation to completion from a synchronous context.
///
/// libbox calls our platform-interface methods synchronously on Go threads, but
/// some of the work they must do (e.g. `setTunnelNetworkSettings`) is async.
/// Blocking one of those Go threads on a semaphore is safe — they are not part
/// of Swift's cooperative pool — and mirrors sing-box-for-apple's own bridge.
func runBlocking<T>(_ operation: @escaping () async throws -> T) throws -> T {
    let semaphore = DispatchSemaphore(value: 0)
    let box = ResultBox<T>()
    Task {
        do {
            box.result = try await .success(operation())
        } catch {
            box.result = .failure(error)
        }
        semaphore.signal()
    }
    semaphore.wait()
    return try box.result!.get()
}

/// Non-throwing variant.
func runBlocking<T>(_ operation: @escaping () async -> T) -> T {
    let semaphore = DispatchSemaphore(value: 0)
    let box = ResultBox<T>()
    Task {
        box.result = await .success(operation())
        semaphore.signal()
    }
    semaphore.wait()
    return try! box.result!.get()
}

private final class ResultBox<T> {
    var result: Result<T, Error>?
}
