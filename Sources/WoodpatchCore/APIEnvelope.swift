// APIEnvelope.swift
// ────────────────────────────────────────────────────────────────────
// Wire-level types for the BOS API envelope. Every 2xx response carries
// `{success: true, data: <T>, meta: {...}}`, and every 4xx/5xx carries
// `{success: false, error: {code, message}, meta: {...}}`. 204 responses
// are bodyless.
//
// Generic over the META type as well as the payload: the `meta` block
// has a common core (request id, timestamp, pagination), but some
// surfaces add their own fields (the softphone's comms inbox adds
// `total_unread`). Each app either uses `APIStandardMeta` or declares its
// own meta struct, so no app-specific field lives here.
//
// The app's API client inspects the envelope and unwraps success → T or
// throws `APIClientError.api(...)`. These shapes are wire-model details
// and shouldn't leak past the client's public surface.
//
// Extracted from the softphone (Networking/APIResponse.swift) for BOS
// #2562, with the meta made generic.

import Foundation

/// The response envelope. `Payload` is the per-endpoint type; `Meta` is
/// `APIStandardMeta` unless the surface adds meta fields of its own.
public struct APIEnvelope<Payload: Decodable & Sendable, Meta: Decodable & Sendable>: Decodable,
    Sendable
{
    public let success: Bool
    public let data: Payload?
    public let error: APIErrorBody?
    public let meta: Meta?
}

/// The common `meta` block. Every field is optional in practice:
/// `request_id` mirrors the response header and `timestamp` is
/// informational.
public struct APIStandardMeta: Decodable, Sendable, Equatable {
    public let requestId: String?
    public let timestamp: String?
    /// Cursor pagination: present on cursor-paginated list responses.
    public let nextCursor: String?
    public let hasMore: Bool?
    /// Page-based pagination (the Laravel paginator envelope:
    /// `meta.pagination.{current_page,last_page,…}`).
    public let pagination: APIPagination?

    public init(
        requestId: String? = nil,
        timestamp: String? = nil,
        nextCursor: String? = nil,
        hasMore: Bool? = nil,
        pagination: APIPagination? = nil
    ) {
        self.requestId = requestId
        self.timestamp = timestamp
        self.nextCursor = nextCursor
        self.hasMore = hasMore
        self.pagination = pagination
    }

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id"
        case timestamp
        case nextCursor = "next_cursor"
        case hasMore = "has_more"
        case pagination
    }
}

/// The nested page block of Foundation's `ApiResponse::paginated`.
public struct APIPagination: Decodable, Sendable, Equatable {
    public let currentPage: Int?
    public let lastPage: Int?
    public let perPage: Int?
    public let total: Int?

    public init(currentPage: Int? = nil, lastPage: Int? = nil, perPage: Int? = nil, total: Int? = nil) {
        self.currentPage = currentPage
        self.lastPage = lastPage
        self.perPage = perPage
        self.total = total
    }

    enum CodingKeys: String, CodingKey {
        case currentPage = "current_page"
        case lastPage = "last_page"
        case perPage = "per_page"
        case total
    }
}

/// The `error` block on a 4xx/5xx envelope.
public struct APIErrorBody: Decodable, Sendable, Equatable {
    public let code: String
    public let message: String

    public init(code: String, message: String) {
        self.code = code
        self.message = message
    }
}
