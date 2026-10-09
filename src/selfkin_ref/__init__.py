# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Selfkin reference contributors
"""Selfkin reference implementation (draft, not for production).

A small, readable Python implementation of the core of the Selfkin draft
standards (https://github.com/selfkin/standards): identities, the signed
Selfkin Envelope, capability tokens, privacy reports, and a simplified
end-to-end session. It exists to make the drafts concrete and testable.
It is not a secure product and must not be used to protect real data.
"""

__version__ = "0.1.0.dev0"
SPEC_VERSION = "0.1"
