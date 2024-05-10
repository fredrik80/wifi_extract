/*
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program. If not, see <https://www.gnu.org/licenses/>.
*/


#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <wlanapi.h>
#include <iostream>
#include "tinyxml2.h"

// This program connects to the Windows WLAN API to retrieve and display WiFi profiles and their passwords.
// It lists SSID, authentication method, and plaintext password of each profile stored by the WLAN service on the system.
// Inspired by John Hammond

// Ensures linkage with necessary libraries for WLAN API and COM services.
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

int wmain() {
    HANDLE hClient = NULL;
    DWORD dwCurVersion = 0;

    // Initialize WLAN handle
    DWORD dwResult = WlanOpenHandle(WLAN_API_VERSION, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        std::wcerr << L"WlanOpenHandle failed with error: " << dwResult << std::endl;
        return 1;
    }

    PWLAN_INTERFACE_INFO_LIST pInterfaceList = NULL;
    PWLAN_INTERFACE_INFO pInterfaceInfo = NULL;

    // Enumerate available WLAN interfaces
    dwResult = WlanEnumInterfaces(hClient, NULL, &pInterfaceList);
    if (dwResult != ERROR_SUCCESS) {
        std::wcerr << L"WlanEnumInterfaces failed with error: " << dwResult << std::endl;
        WlanCloseHandle(hClient, NULL);
        return 1;
    }

    // Process each available interface
    for (DWORD i = 0; i < pInterfaceList->dwNumberOfItems; i++) {
        pInterfaceInfo = &pInterfaceList->InterfaceInfo[i];

        // Print the header for new interface block
        std::wcout << L"\n[*] Wifi Password unhider [*]\n" << std::endl;

        PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
        dwResult = WlanGetProfileList(hClient, &pInterfaceInfo->InterfaceGuid, NULL, &pProfileList);
        if (dwResult != ERROR_SUCCESS) {
            std::wcerr << L"WlanGetProfileList failed with error: " << dwResult << std::endl;
        }

        // Retrieve and display profiles and passwords for each interface
        for (int j = 0; j < (int)pProfileList->dwNumberOfItems; j++) {
            PWLAN_PROFILE_INFO pProfileInfo = &pProfileList->ProfileInfo[j];
            LPWSTR pProfileXml = NULL;
            DWORD dwFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            DWORD dwAccess = 0;
            dwResult = WlanGetProfile(hClient, &pInterfaceInfo->InterfaceGuid, pProfileInfo->strProfileName, NULL, &pProfileXml, &dwFlags, &dwAccess);

            if (dwResult == ERROR_SUCCESS) {
                std::wstring ws(pProfileXml);  // Convert XML data to std::wstring
                std::string profileXmlStr(ws.begin(), ws.end());  // Convert std::wstring to std::string

                tinyxml2::XMLDocument doc;
                doc.Parse(profileXmlStr.c_str());
                tinyxml2::XMLElement* ssidElement = doc.FirstChildElement("WLANProfile")->FirstChildElement("SSIDConfig")->FirstChildElement("SSID")->FirstChildElement("name");
                tinyxml2::XMLElement* keyMaterialElement = doc.FirstChildElement("WLANProfile")->FirstChildElement("MSM")->FirstChildElement("security")->FirstChildElement("sharedKey")->FirstChildElement("keyMaterial");
                tinyxml2::XMLElement* securityElement = doc.FirstChildElement("WLANProfile")->FirstChildElement("MSM")->FirstChildElement("security")->FirstChildElement("authEncryption")->FirstChildElement("authentication");

                if (ssidElement && keyMaterialElement) {
                    std::wcout << L"[+] SSID: " << ssidElement->GetText() << L" ::Authentication: " << securityElement->GetText() << L" ::Password: " << keyMaterialElement->GetText() << std::endl;
                }
            }
            else {
                std::wcerr << L"WlanGetProfile failed with error: " << dwResult << std::endl;
            }
            if (pProfileXml) {
                WlanFreeMemory(pProfileXml);
            }
        }

        if (pProfileList) {
            WlanFreeMemory(pProfileList);
        }
    }

    if (pInterfaceList) {
        WlanFreeMemory(pInterfaceList);
    }

    WlanCloseHandle(hClient, NULL);
    return 0;
}
