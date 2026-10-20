// SPDX-License-Identifier: AGPL-3.0-only

// Package wtp is a native Go implementation of the Wutong Protocol (WTP wutong/0.1,
// spec revision v0.1.2) wire layer: the strict JSON profile, RFC 8785 JCS, the
// deterministic CBOR profile, SHA-256 digests, Ed25519 envelope signatures, the Task
// state machine and portable relative paths.
//
// It deliberately avoids cgo so it can be cross-compiled freely. Behaviour is pinned to
// the cross-language vectors published in github.com/project-wutong/wutong-protocol.
//
// Values use a restricted data model: map[string]any, []any, string, int64, bool, nil.
package wtp

// Protocol is the WTP protocol identifier.
const Protocol = "wutong/0.1"

// Implementation identifies this SDK in node metadata.
const Implementation = "wutong-sdk-go/0.1.0"
