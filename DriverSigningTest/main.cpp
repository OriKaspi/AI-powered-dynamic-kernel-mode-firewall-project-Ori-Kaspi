// 1. MUST BE FIRST: This tells the compiler how to handle GUIDs
#include <initguid.h>

// 2. MUST BE SECOND: This defines the NDIS version so NET_BUFFER_LIST is found
#define NDIS_SUPPORT_NDIS630 1
#include <ndis.h>

// 3. Standard Kernel Headers
#include <ntddk.h>

// 4. WFP Headers
#include <fwpmk.h>
#include <fwpsk.h>
#pragma comment(lib, "fwpclnt.lib")
#pragma comment(lib, "netio.lib")
extern "C" {
    DRIVER_INITIALIZE DriverEntry;
    DRIVER_UNLOAD UnloadDriver;

    // Use the 6-parameter version for modern WDK
    void NTAPI MyClassifyFn(
        const FWPS_INCOMING_VALUES0* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
        void* layerData,
        const FWPS_FILTER0* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0* classifyOut);

    NTSTATUS NTAPI MyNotifyFn(
        FWPS_CALLOUT_NOTIFY_TYPE notifyType,
        const GUID* filterKey,
        FWPS_FILTER0* filter);

    void NTAPI MyFlowDeleteFn(
        UINT16 layerId,
        UINT32 calloutId,
        UINT64 flowContext);
}

// Global GUID for our callout
// {B6376916-4190-4820-9D45-667C1C45E67A}
DEFINE_GUID(MY_CALLOUT_GUID, 0xb6376916, 0x4190, 0x4820, 0x9d, 0x45, 0x66, 0x7c, 0x1c, 0x45, 0xe6, 0x7a);

HANDLE g_EngineHandle = NULL;
UINT32 g_CalloutId = 0;
UINT64 g_FilterId = 0;

void NTAPI MyClassifyFn(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // Extract Remote IP (IPv4)
    UINT32 remoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;

    // Print to DbgView
    DbgPrint("WFP: Packet from IP %u.%u.%u.%u\n",
        (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF);

    classifyOut->actionType = FWP_ACTION_PERMIT;
}

NTSTATUS NTAPI MyNotifyFn(FWPS_CALLOUT_NOTIFY_TYPE notifyType, const GUID* filterKey, FWPS_FILTER0* filter) {
    UNREFERENCED_PARAMETER(notifyType); UNREFERENCED_PARAMETER(filterKey); UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

void NTAPI MyFlowDeleteFn(UINT16 layerId, UINT32 calloutId, UINT64 flowContext) {
    UNREFERENCED_PARAMETER(layerId); UNREFERENCED_PARAMETER(calloutId); UNREFERENCED_PARAMETER(flowContext);
}

void UnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    if (g_EngineHandle) {
        FwpmFilterDeleteById0(g_EngineHandle, g_FilterId);
        FwpmCalloutDeleteById0(g_EngineHandle, g_CalloutId);
        FwpsCalloutUnregisterById0(g_CalloutId);
        FwpmEngineClose0(g_EngineHandle);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = UnloadDriver;

    NTSTATUS status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_EngineHandle);
    if (!NT_SUCCESS(status)) return status;

    FWPS_CALLOUT0 sCallout = { 0 };
    sCallout.calloutKey = MY_CALLOUT_GUID;
    sCallout.classifyFn = MyClassifyFn;
    sCallout.notifyFn = MyNotifyFn;
    sCallout.flowDeleteFn = MyFlowDeleteFn;

    status = FwpsCalloutRegister0(DriverObject, &sCallout, &g_CalloutId);
    if (!NT_SUCCESS(status)) return status;

    FWPM_CALLOUT0 mCallout = { 0 };
    mCallout.calloutKey = MY_CALLOUT_GUID;
    mCallout.displayData.name = (wchar_t*)L"MyCallout";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) return status;

    FWPM_FILTER0 mFilter = { 0 };
    mFilter.displayData.name = (wchar_t*)L"MyFilter";
    mFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    mFilter.action.calloutKey = MY_CALLOUT_GUID;

    return FwpmFilterAdd0(g_EngineHandle, &mFilter, NULL, &g_FilterId);
}