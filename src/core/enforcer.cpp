#include "core/enforcer.h"

#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>

#include <cstdio>

namespace ng {
namespace {

// NeuralGuard's own WFP provider + sublayer identities.
// {b8d0f1a2-3c4d-4e5f-9a0b-1c2d3e4f5061} / ...5062
const GUID kProviderGuid =
    {0xb8d0f1a2, 0x3c4d, 0x4e5f, {0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61}};
const GUID kSubLayerGuid =
    {0xb8d0f1a2, 0x3c4d, 0x4e5f, {0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x62}};

// The ALE layers we install filters at (outbound connect + inbound accept).
const GUID kLayers[] = {
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
};

int DeleteOurFiltersInLayer(HANDLE eng, const GUID& layer) {
    HANDLE h = nullptr;
    FWPM_FILTER_ENUM_TEMPLATE0 t{};
    t.layerKey = layer;
    t.enumType = FWP_FILTER_ENUM_OVERLAPPING;
    t.flags = FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
    t.actionMask = 0xFFFFFFFF;
    if (FwpmFilterCreateEnumHandle0(eng, &t, &h) != ERROR_SUCCESS) return 0;

    int deleted = 0;
    FWPM_FILTER0** arr = nullptr;
    UINT32 n = 0;
    while (FwpmFilterEnum0(eng, h, 64, &arr, &n) == ERROR_SUCCESS && n > 0) {
        for (UINT32 i = 0; i < n; ++i) {
            if (arr[i]->providerKey && IsEqualGUID(*arr[i]->providerKey, kProviderGuid)) {
                if (FwpmFilterDeleteById0(eng, arr[i]->filterId) == ERROR_SUCCESS) ++deleted;
            }
        }
        FwpmFreeMemory0((void**)&arr);
        if (n < 64) break;
    }
    FwpmFilterDestroyEnumHandle0(eng, h);
    return deleted;
}

int CountOurFiltersInLayer(HANDLE eng, const GUID& layer) {
    HANDLE h = nullptr;
    FWPM_FILTER_ENUM_TEMPLATE0 t{};
    t.layerKey = layer;
    t.enumType = FWP_FILTER_ENUM_OVERLAPPING;
    t.flags = FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
    t.actionMask = 0xFFFFFFFF;
    if (FwpmFilterCreateEnumHandle0(eng, &t, &h) != ERROR_SUCCESS) return 0;

    int count = 0;
    FWPM_FILTER0** arr = nullptr;
    UINT32 n = 0;
    while (FwpmFilterEnum0(eng, h, 64, &arr, &n) == ERROR_SUCCESS && n > 0) {
        for (UINT32 i = 0; i < n; ++i)
            if (arr[i]->providerKey && IsEqualGUID(*arr[i]->providerKey, kProviderGuid)) ++count;
        FwpmFreeMemory0((void**)&arr);
        if (n < 64) break;
    }
    FwpmFilterDestroyEnumHandle0(eng, h);
    return count;
}

}  // namespace

Enforcer::~Enforcer() { close(); }

bool Enforcer::ensureObjects() {
    HANDLE eng = (HANDLE)engine_;

    FWPM_PROVIDER0 provider{};
    provider.providerKey = kProviderGuid;
    provider.displayData.name = const_cast<wchar_t*>(L"NeuralGuard");
    provider.displayData.description = const_cast<wchar_t*>(L"NeuralGuard firewall provider");
    DWORD e = FwpmProviderAdd0(eng, &provider, nullptr);
    if (e != ERROR_SUCCESS && e != FWP_E_ALREADY_EXISTS) {
        fprintf(stderr, "FwpmProviderAdd0 failed: 0x%08lX\n", e);
        return false;
    }

    FWPM_SUBLAYER0 sub{};
    sub.subLayerKey = kSubLayerGuid;
    sub.displayData.name = const_cast<wchar_t*>(L"NeuralGuard");
    sub.providerKey = const_cast<GUID*>(&kProviderGuid);
    sub.weight = 0xFFFF;  // above Windows Defender Firewall's sublayers
    e = FwpmSubLayerAdd0(eng, &sub, nullptr);
    if (e != ERROR_SUCCESS && e != FWP_E_ALREADY_EXISTS) {
        fprintf(stderr, "FwpmSubLayerAdd0 failed: 0x%08lX\n", e);
        return false;
    }
    return true;
}

bool Enforcer::open() {
    HANDLE eng = nullptr;
    DWORD e = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &eng);
    if (e != ERROR_SUCCESS) {
        fprintf(stderr, "FwpmEngineOpen0 failed: 0x%08lX (are you elevated?)\n", e);
        return false;
    }
    engine_ = eng;
    return ensureObjects();
}

void Enforcer::close() {
    if (engine_) { FwpmEngineClose0((HANDLE)engine_); engine_ = nullptr; }
}

bool Enforcer::addRemoteIpv4Rule(uint32_t ipv4Host, uint16_t port, uint8_t proto, bool block) {
    HANDLE eng = (HANDLE)engine_;

    FWPM_FILTER_CONDITION0 conds[3];
    UINT32 nc = 0;
    conds[nc].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conds[nc].matchType = FWP_MATCH_EQUAL;
    conds[nc].conditionValue.type = FWP_UINT32;
    conds[nc].conditionValue.uint32 = ipv4Host;
    ++nc;
    if (port) {
        conds[nc].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conds[nc].matchType = FWP_MATCH_EQUAL;
        conds[nc].conditionValue.type = FWP_UINT16;
        conds[nc].conditionValue.uint16 = port;
        ++nc;
    }
    if (proto) {
        conds[nc].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        conds[nc].matchType = FWP_MATCH_EQUAL;
        conds[nc].conditionValue.type = FWP_UINT8;
        conds[nc].conditionValue.uint8 = proto;
        ++nc;
    }

    FWPM_FILTER0 filter{};
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = kSubLayerGuid;
    filter.providerKey = const_cast<GUID*>(&kProviderGuid);
    filter.displayData.name = const_cast<wchar_t*>(block ? L"NeuralGuard block"
                                                         : L"NeuralGuard permit");
    filter.action.type = block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
    filter.weight.type = FWP_EMPTY;  // let BFE assign a weight
    filter.numFilterConditions = nc;
    filter.filterCondition = conds;

    UINT64 id = 0;
    DWORD e = FwpmFilterAdd0(eng, &filter, nullptr, &id);
    if (e != ERROR_SUCCESS) {
        fprintf(stderr, "FwpmFilterAdd0 failed: 0x%08lX\n", e);
        return false;
    }
    return true;
}

int Enforcer::countRules() {
    int n = 0;
    for (const GUID& layer : kLayers) n += CountOurFiltersInLayer((HANDLE)engine_, layer);
    return n;
}

int Enforcer::panic() {
    HANDLE eng = (HANDLE)engine_;
    int deleted = 0;
    for (const GUID& layer : kLayers) deleted += DeleteOurFiltersInLayer(eng, layer);
    // Now that no filters reference it, drop the sublayer (best effort).
    FwpmSubLayerDeleteByKey0(eng, &kSubLayerGuid);
    FwpmProviderDeleteByKey0(eng, &kProviderGuid);
    return deleted;
}

}  // namespace ng
