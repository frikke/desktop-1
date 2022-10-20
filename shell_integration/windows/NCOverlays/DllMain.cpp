/**
 * Copyright (c) 2000-2013 Liferay, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

#include "NCOverlayRegistrationHandler.h"
#include "NCOverlayFactory.h"
#include "WinShellExtConstants.h"

#include <fstream>
#include <iostream>

HINSTANCE instanceHandle = nullptr;

long dllReferenceCount = 0;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCOverlays " << "DllMain" << std::endl;

    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            instanceHandle = hModule;
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}

HRESULT CreateFactory(REFIID riid, void **ppv, int state)
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCOverlays " << "CreateFactory" << std::endl;

    HRESULT hResult = E_OUTOFMEMORY;

    NCOverlayFactory* ncOverlayFactory = new NCOverlayFactory(state);

    if (ncOverlayFactory) {
        hResult = ncOverlayFactory->QueryInterface(riid, ppv);
        ncOverlayFactory->Release();
    }
    return hResult;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void **ppv)
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCOverlays " << "DllGetClassObject" << std::endl;

    HRESULT hResult = CLASS_E_CLASSNOTAVAILABLE;
    GUID guid;
 
    hResult = CLSIDFromString(OVERLAY_GUID_ERROR, (LPCLSID)&guid);
    if (!SUCCEEDED(hResult)) { return hResult; }
    if (IsEqualCLSID(guid, rclsid)) { return CreateFactory(riid, ppv, State_Error); }

    hResult = CLSIDFromString(OVERLAY_GUID_OK, (LPCLSID)&guid);
    if (!SUCCEEDED(hResult)) { return hResult; }
    if (IsEqualCLSID(guid, rclsid)) { return CreateFactory(riid, ppv, State_OK); }

    hResult = CLSIDFromString(OVERLAY_GUID_OK_SHARED, (LPCLSID)&guid);
    if (!SUCCEEDED(hResult)) { return hResult; }
    if (IsEqualCLSID(guid, rclsid)) { return CreateFactory(riid, ppv, State_OKShared); }

    hResult = CLSIDFromString(OVERLAY_GUID_SYNC, (LPCLSID)&guid);
    if (!SUCCEEDED(hResult)) { return hResult; }
    if (IsEqualCLSID(guid, rclsid)) { return CreateFactory(riid, ppv, State_Sync); }

    hResult = CLSIDFromString(OVERLAY_GUID_WARNING, (LPCLSID)&guid);
    if (!SUCCEEDED(hResult)) { return hResult; }
    if (IsEqualCLSID(guid, rclsid)) { return CreateFactory(riid, ppv, State_Warning); }

    return CLASS_E_CLASSNOTAVAILABLE;
}

STDAPI DllCanUnloadNow(void)
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCOverlays " << "DllCanUnloadNow" << std::endl;

    return dllReferenceCount > 0 ? S_FALSE : S_OK;
}

HRESULT RegisterCLSID(LPCOLESTR guidStr, PCWSTR overlayStr, PCWSTR szModule)
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCOverlays " << "RegisterCLSID" << std::endl;

    HRESULT hResult = S_OK;

    GUID guid;
    hResult = CLSIDFromString(guidStr, (LPCLSID)&guid);

    if (hResult != S_OK) {
        return hResult;
    }

    hResult = NCOverlayRegistrationHandler::RegisterCOMObject(szModule, OVERLAY_DESCRIPTION, guid);

    if (!SUCCEEDED(hResult)) {
        return hResult;
    }

    hResult = NCOverlayRegistrationHandler::MakeRegistryEntries(guid, overlayStr);

    return hResult;
}

HRESULT UnregisterCLSID(LPCOLESTR guidStr, PCWSTR overlayStr)
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCOverlays " << "UnregisterCLSID" << std::endl;

    HRESULT hResult = S_OK;
    GUID guid;

    hResult = CLSIDFromString(guidStr, (LPCLSID)&guid);

    if (hResult != S_OK) {
        return hResult;
    }

    hResult = NCOverlayRegistrationHandler::UnregisterCOMObject(guid);

    if (!SUCCEEDED(hResult)) {
        return hResult;
    }

    hResult = NCOverlayRegistrationHandler::RemoveRegistryEntries(overlayStr);

    return hResult;
}

HRESULT _stdcall DllRegisterServer(void)
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCOverlays " << "DllRegisterServer" << std::endl;

    HRESULT hResult = S_OK;

    wchar_t szModule[MAX_PATH];

    if (GetModuleFileName(instanceHandle, szModule, ARRAYSIZE(szModule)) == 0) {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        return hResult;
    }

    hResult = RegisterCLSID(OVERLAY_GUID_ERROR, OVERLAY_NAME_ERROR, szModule);
    if (!SUCCEEDED(hResult)) { return hResult; }
    hResult = RegisterCLSID(OVERLAY_GUID_OK, OVERLAY_NAME_OK, szModule);
    if (!SUCCEEDED(hResult)) { return hResult; }
    hResult = RegisterCLSID(OVERLAY_GUID_OK_SHARED, OVERLAY_NAME_OK_SHARED, szModule);
    if (!SUCCEEDED(hResult)) { return hResult; }
    hResult = RegisterCLSID(OVERLAY_GUID_SYNC, OVERLAY_NAME_SYNC, szModule);
    if (!SUCCEEDED(hResult)) { return hResult; }
    hResult = RegisterCLSID(OVERLAY_GUID_WARNING, OVERLAY_NAME_WARNING, szModule);

    return hResult;
}

STDAPI DllUnregisterServer(void)
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCOverlays " << "DllUnregisterServer" << std::endl;

    HRESULT hResult = S_OK;

    wchar_t szModule[MAX_PATH];
    
    if (GetModuleFileNameW(instanceHandle, szModule, ARRAYSIZE(szModule)) == 0)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        return hResult;
    }

    hResult = UnregisterCLSID(OVERLAY_GUID_ERROR, OVERLAY_NAME_ERROR);
    if (!SUCCEEDED(hResult)) { return hResult; }
    hResult = UnregisterCLSID(OVERLAY_GUID_OK, OVERLAY_NAME_OK);
    if (!SUCCEEDED(hResult)) { return hResult; }
    hResult = UnregisterCLSID(OVERLAY_GUID_OK_SHARED, OVERLAY_NAME_OK_SHARED);
    if (!SUCCEEDED(hResult)) { return hResult; }
    hResult = UnregisterCLSID(OVERLAY_GUID_SYNC, OVERLAY_NAME_SYNC);
    if (!SUCCEEDED(hResult)) { return hResult; }
    hResult = UnregisterCLSID(OVERLAY_GUID_WARNING, OVERLAY_NAME_WARNING);

    return hResult;
}
