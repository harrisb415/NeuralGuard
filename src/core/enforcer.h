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

    // Turn on default-deny for OUTBOUND IPv4 AND IPv6 (ALE_AUTH_CONNECT_V4/V6):
    // install the Tier-0 always-exempt permits (loopback, private/ULA/link-local
    // ranges, IPv6 multicast, DNS, DHCP/DHCPv6, NTP) plus a catch-all block at
    // each layer. Inbound is deliberately left untouched so an inbound-initiated
    // session (e.g. SSH) can't be cut off. Call panic() to revert. Returns true
    // on success.
    bool enableDefaultDeny();

    // Turn on default-deny for INBOUND accepts (ALE_AUTH_RECV_ACCEPT_V4/V6): a
    // catch-all block plus the anti-lockout Tier-0 permits installed FIRST -
    // SSH (22) + RDP (3389) local ports, DHCP/DHCPv6 replies, loopback and
    // link-local peers. Inbound default-deny only affects NEW inbound accepts to
    // your listening services; the return traffic of connections you initiated
    // outbound is never re-classified here, so it is unaffected. Call panic() to
    // revert. Returns true on success.
    bool enableInboundDefaultDeny();

    // Permit an application to ACCEPT inbound connections (by its on-disk path),
    // optionally restricted to a local service port / protocol (0 = any). Used to
    // auto-permit the learned inbound baseline before inbound default-deny.
    bool addPermitAppIdInbound(const wchar_t* dosPath, uint16_t localPort, uint8_t proto);

    // Permit a specific application (by its on-disk path) to make outbound IPv4
    // connections, optionally restricted to a remote port / protocol (0 = any).
    // Used to auto-permit the observed baseline before default-deny.
    bool addPermitAppId(const wchar_t* dosPath, uint16_t port, uint8_t proto);

    // Apply one user-editable rule as a WFP filter. appPath (NULL/empty = any
    // app), remoteIpv4Host (0 = any, host byte order), port (0 = any), proto
    // (0 = any). block=false permits. User permits sit just above the baseline;
    // user blocks sit above everything so an explicit block always wins.
    bool applyUserRule(const wchar_t* appPath, uint32_t remoteIpv4Host,
                       uint16_t port, uint8_t proto, bool block);

    // True if `filterId` is one of OUR inbound catch-all blocks - i.e. this drop
    // is ours and the user could choose to permit it, as opposed to one of the
    // many inbound drops Windows Firewall makes on its own. Used to keep the
    // "blocked inbound services" review list free of other providers' decisions.
    bool isOurInboundBlock(unsigned long long filterId) const {
        return filterId != 0 && (filterId == inBlockV4_ || filterId == inBlockV6_);
    }

    int  countRules();   // NeuralGuard filters currently installed

    // Delete just our filters (keep the sublayer/provider), for a live re-apply.
    int  clearFilters();

    // Delete ALL NeuralGuard filters and our sublayer/provider. Returns the
    // number of filters removed. This is the panic / fail-open path.
    int  panic();

private:
    bool ensureObjects();
    // Low-level outbound filter helpers (weight: higher wins; block uses 0).
    // addV4/addV6 install the same conditions at CONNECT_V4 / CONNECT_V6.
    bool addV4(bool block, void* conds, unsigned nc, unsigned char weight,
               const wchar_t* name);
    bool addV6(bool block, void* conds, unsigned nc, unsigned char weight,
               const wchar_t* name);
    bool addPermitCidrV4(uint32_t addrHost, uint32_t maskHost);
    bool addPermitRemotePortV4(uint16_t port, uint8_t proto);
    bool addPermitCidrV6(const unsigned char addr[16], unsigned char prefixLen);
    bool addPermitRemotePortV6(uint16_t port, uint8_t proto);
    // Inbound (RECV_ACCEPT) Tier-0 helpers - exempt by local service port (both
    // versions) or by remote peer subnet. weight 15, above the inbound catch-all.
    bool addPermitLocalPortIn(uint16_t localPort, uint8_t proto);
    bool addPermitCidrInV4(uint32_t addrHost, uint32_t maskHost);
    bool addPermitCidrInV6(const unsigned char addr[16], unsigned char prefixLen);
    void* engine_ = nullptr;  // HANDLE
    // Filter ids of the inbound catch-all blocks, so a drop can be attributed to
    // us (see isOurInboundBlock). Reset by panic()/clearFilters().
    unsigned long long inBlockV4_ = 0, inBlockV6_ = 0;
};

}  // namespace ng
