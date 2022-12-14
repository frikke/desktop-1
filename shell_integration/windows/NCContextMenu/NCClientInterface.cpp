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

#include "NCClientInterface.h"

#include "CommunicationSocket.h"
#include "StringUtil.h"

#include <shlobj.h>

#include <Strsafe.h>

#include <algorithm>
#include <iostream>
#include <sstream>
#include <iterator>
#include <unordered_set>

#include <fstream>
#include <locale>
#include <codecvt>

using namespace std;

#define PIPE_TIMEOUT  5*1000 //ms

std::string ws2s(const std::wstring &wstr)
{
    using convert_typeX = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;

    return converterX.to_bytes(wstr);
}

NCClientInterface::ContextMenuInfo NCClientInterface::FetchInfo(const std::wstring &files)
{
    auto pipename = CommunicationSocket::DefaultPipePath();

    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCClientInterface " << "FetchInfo " << "pipename: " << ws2s(pipename) << std::endl;

    CommunicationSocket socket;
    if (!WaitNamedPipe(pipename.data(), PIPE_TIMEOUT)) {
        return {};
    }
    if (!socket.Connect(pipename)) {
        return {};
    }
    socket.SendMsg(L"GET_STRINGS:CONTEXT_MENU_TITLE\n");
    socket.SendMsg((L"GET_MENU_ITEMS:" + files + L"\n").data());

    ContextMenuInfo info;
    std::wstring response;
    int sleptCount = 0;
    while (sleptCount < 5) {
        if (socket.ReadLine(&response)) {
            if (StringUtil::begins_with(response, wstring(L"REGISTER_PATH:"))) {
                wstring responsePath = response.substr(14); // length of REGISTER_PATH
                info.watchedDirectories.push_back(responsePath);
            }
            else if (StringUtil::begins_with(response, wstring(L"STRING:"))) {
                wstring stringName, stringValue;
                if (!StringUtil::extractChunks(response, stringName, stringValue))
                    continue;
                if (stringName == L"CONTEXT_MENU_TITLE")
                    info.contextMenuTitle = move(stringValue);
            } else if (StringUtil::begins_with(response, wstring(L"MENU_ITEM:"))) {
                wstring commandName, flags, title;
                if (!StringUtil::extractChunks(response, commandName, flags, title))
                    continue;
                info.menuItems.push_back({ commandName, flags, title });
            } else if (StringUtil::begins_with(response, wstring(L"GET_MENU_ITEMS:END"))) {
                break; // Stop once we completely received the last sent request
            }
        }
        else {
            Sleep(50);
            ++sleptCount;
        }
    }
    return info;
}

void NCClientInterface::SendRequest(const wchar_t *verb, const std::wstring &path)
{
    auto pipename = CommunicationSocket::DefaultPipePath();

    const auto appdataPath = std::string{getenv("APPDATA")};
    std::ofstream logOutput(appdataPath + "\\Nextcloud\\shellext.log", std::ios::out | std::ios::app);

    logOutput << "NCClientInterface " << "SendRequest " << "pipename: " << ws2s(pipename) << std::endl;

    CommunicationSocket socket;
    if (!WaitNamedPipe(pipename.data(), PIPE_TIMEOUT)) {
        return;
    }
    if (!socket.Connect(pipename)) {
        return;
    }

    socket.SendMsg((verb + (L":" + path + L"\n")).data());
}
