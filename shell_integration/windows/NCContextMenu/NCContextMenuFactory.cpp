/**
* Copyright (c) 2015 Daniel Molkentin <danimo@owncloud.com>. All rights reserved.
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

#include "NCContextMenuFactory.h"
#include "NCContextMenu.h"
#include <new>
#include <Shlwapi.h>
#include <fstream>
#include <iostream>
#pragma comment(lib, "shlwapi.lib")


extern long g_cDllRef;


NCContextMenuFactory::NCContextMenuFactory() : m_cRef(1)
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCContextMenuFactory " << "NCContextMenuFactory" << std::endl;

    InterlockedIncrement(&g_cDllRef);
}

NCContextMenuFactory::~NCContextMenuFactory()
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCContextMenuFactory " << "~NCContextMenuFactory" << std::endl;

    InterlockedDecrement(&g_cDllRef);
}


// IUnknown methods

IFACEMETHODIMP NCContextMenuFactory::QueryInterface(REFIID riid, void **ppv)
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCContextMenuFactory " << "QueryInterface" << std::endl;

    static const QITAB qit[] =  { QITABENT(NCContextMenuFactory, IClassFactory), { 0 }, };
    return QISearch(this, qit, riid, ppv);
}

IFACEMETHODIMP_(ULONG) NCContextMenuFactory::AddRef()
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCContextMenuFactory " << "AddRef" << std::endl;

    return InterlockedIncrement(&m_cRef);
}

IFACEMETHODIMP_(ULONG) NCContextMenuFactory::Release()
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCContextMenuFactory " << "Release" << std::endl;

    ULONG cRef = InterlockedDecrement(&m_cRef);
    if (0 == cRef) {
        delete this;
    }
    return cRef;
}


// IClassFactory methods

IFACEMETHODIMP NCContextMenuFactory::CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppv)
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCContextMenuFactory " << "CreateInstance" << std::endl;

    HRESULT hr = CLASS_E_NOAGGREGATION;

    // pUnkOuter is used for aggregation. We do not support it in the sample.
    if (!pUnkOuter) {
        hr = E_OUTOFMEMORY;

        // Create the COM component.
        NCContextMenu *pExt = new (std::nothrow) NCContextMenu();
        if (pExt) {
            // Query the specified interface.
            hr = pExt->QueryInterface(riid, ppv);
            pExt->Release();
        }
    }

    return hr;
}

IFACEMETHODIMP NCContextMenuFactory::LockServer(BOOL fLock)
{
    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCContextMenuFactory " << "LockServer" << std::endl;

    if (fLock)  {
        InterlockedIncrement(&g_cDllRef);
    } else {
        InterlockedDecrement(&g_cDllRef);
    }
    return S_OK;
}
