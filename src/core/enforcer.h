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

    int  countRules();   // NeuralGuard filters currently installed

    // Delete ALL NeuralGuard filters and our sublayer/provider. Returns the
    // number of filters removed. This is the panic / fail-open path.
    int  panic();

private:
    bool ensureObjects();
    void* engine_ = nullptr;  // HANDLE
};

}  // namespace ng
