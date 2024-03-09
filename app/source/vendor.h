#pragma once

#define WIN32_LEAN_AND_MEAN
#define CURL_STATICLIB
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define API_KEY "11111111111111111111111111111111"

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <vector>
#include <iostream>
#include <TlHelp32.h>
#include <fstream>
#include <thread>
#include <Shlwapi.h>
#include <psapi.h>

#pragma comment(lib, "Shlwapi.lib")

#pragma region curl_stuff
#pragma comment (lib,"Normaliz.lib")
#pragma comment (lib,"Ws2_32.lib")
#pragma comment (lib,"Wldap32.lib")
#pragma comment (lib,"Crypt32.lib")

#include <curl.h>
#ifdef _DEBUG
#    pragma comment (lib,"libcurl_a_debug.lib")
#else
#    pragma comment (lib,"libcurl_a.lib")
#endif
#pragma endregion curl_stuff
#include <json.h>
#include <obfuscate.h>

#include "headers/singleton.h"
#include "headers/types.h"
#include "headers/utils.h"
#include "headers/hashing.h"
#include "headers/hellsgate.h"

#include "app/app.h"

#include "headers/protect.h"
#include "headers/b64/b64.h"

