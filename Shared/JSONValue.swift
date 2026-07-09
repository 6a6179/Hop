import Foundation

/// JSON that remains strongly Codable/Hashable while preserving Xray's long-tail
/// client settings without turning every upstream field into a Swift property.
enum JSONValue: Hashable, Codable, Sendable {
    case object([String: JSONValue])
    case array([JSONValue])
    case string(String)
    case number(Double)
    case bool(Bool)
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            self = try .object(container.decode([String: JSONValue].self))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .object(value):
            try container.encode(value)
        case let .array(value):
            try container.encode(value)
        case let .string(value):
            try container.encode(value)
        case let .number(value):
            try container.encode(value)
        case let .bool(value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        }
    }

    var objectValue: [String: JSONValue]? {
        guard case let .object(value) = self else { return nil }
        return value
    }

    var arrayValue: [JSONValue]? {
        guard case let .array(value) = self else { return nil }
        return value
    }

    var stringValue: String? {
        guard case let .string(value) = self else { return nil }
        return value
    }

    var integerValue: Int? {
        guard case let .number(value) = self,
              value.rounded() == value,
              value >= Double(Int.min), value <= Double(Int.max)
        else {
            return nil
        }
        return Int(value)
    }

    var foundationValue: Any {
        switch self {
        case let .object(value):
            value.mapValues(\.foundationValue)
        case let .array(value):
            value.map(\.foundationValue)
        case let .string(value):
            value
        case let .number(value):
            value
        case let .bool(value):
            value
        case .null:
            NSNull()
        }
    }
}
