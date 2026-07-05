// Enforcer: manages NeuralGuard's WFP objects - our provider, a high-weight
// sublayer above Windows Defender Firewall, and permit/block filters at the ALE
// connect/accept layers. Also implements PANIC: delete every NeuralGuard filter
// (and our sublayer) so the machine fails open. Per docs/DESIGN.md, panic is the
// first thing built and the last line of defense against a bad rule locking you out.
#pragma once

#include <cstdint>

namespace ng {

class Enforcer {
public:
    ~Enforcer();

    bool open();    // open the WFP engine; ensure our provider + sublayer exist
    void close();

    // Add a filter matching a remote IPv4 (host byte order) with optional port
    // (0 = any) and protocol (0 = any). block=false adds a permit.
    bool addRemoteIpv4Rule(uint32_t ipv4Host, uint16_t port, uint8_t proto, bool block);

    // Turn on default-deny for OUTBOUND IPv4 (ALE_AUTH_CONNECT_V4): install the
    // Tier-0 always-exempt permits (loopback, private/link-local ranges, DNS,
    // DHCP, NTP) plus a catch-all block. Inbound is deliberately left untouched
    // so an inbound-initiated session (e.g. SSH) can't be cut off. Call panic()
    // to revert. Returns true on success.
    bool enableDefaultDeny();

    int  countRules();   // NeuralGuard filters currently installed

    // Delete ALL NeuralGuard filters and our sublayer/provider. Returns the
    // number of filters removed. This is the panic / fail-open path.
    int  panic();

private:
    bool ensureObjects();
    // Low-level outbound-V4 filter helpers (weight: higher wins; block uses 0).
    bool addV4(bool block, void* conds, unsigned nc, unsigned char weight,
               const wchar_t* name);
    bool addPermitCidrV4(uint32_t addrHost, uint32_t maskHost);
    bool addPermitRemotePortV4(uint16_t port, uint8_t proto);
    void* engine_ = nullptr;  // HANDLE
};

}  // namespace ng
