#pragma once

class utils : public singleton<utils>
{
	public:
		auto string_parser(const std::string& _string) -> std::vector<unsigned char>
		{
			std::vector<unsigned char> bytes;
			std::istringstream iss(_string);

			std::string hexValue;
			while (std::getline(iss, hexValue, ',')) {
				size_t pos = hexValue.find(("0x"));
				if (pos != std::string::npos) {
					hexValue.erase(pos, 2);
				}

				unsigned char byte = static_cast<unsigned char>(std::stoi(hexValue, nullptr, 16));
				bytes.push_back(byte);
			}

			return bytes;
		}

		auto print_hex_array(const std::vector<unsigned char>& _array) -> void
		{
			int count = 0;
			printf("\n\t");
			for (auto it = _array.begin(); it != _array.end(); ++it)
			{
				printf("0x%02X", *it);
				count++;

				if (count % 10 != 0 && std::next(it) != _array.end())
				{
					printf(", ");
				}

				if (count % 10 == 0)
				{
					printf("\n\t");
				}
			}
		}

		auto get_procid(const char* _name) -> DWORD
		{
			DWORD procId = 0;
			HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (hSnap != INVALID_HANDLE_VALUE) {
				PROCESSENTRY32W procEntry;
				procEntry.dwSize = sizeof(procEntry);
				if (Process32First(hSnap, &procEntry)) {
					do 
					{
						wchar_t wszName[MAX_PATH];
						MultiByteToWideChar(CP_ACP, 0, _name, -1, wszName, MAX_PATH);
						if (!_wcsicmp(procEntry.szExeFile, wszName)) {
							procId = procEntry.th32ProcessID;
							break;
						}
					} while (Process32Next(hSnap, &procEntry));
				}
			}
			return procId;
		}

		auto get_teb() -> PTEB
		{
			#if _WIN64
				return (PTEB)__readgsqword(0x30);
			#else
				return (PTEB)__readfsdword(0x16);
			#endif
		}

		auto get_peb() -> PPEB
		{
			return (PPEB)get_teb()->ProcessEnvironmentBlock;
		}

		auto get_eat(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) -> bool
		{
			PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
			if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			{
				return FALSE;
			}

			PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
			if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) 
			{
				return FALSE;
			}

			*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
			return TRUE;
		}

		auto self_delete() -> bool
		{
			WCHAR sz_path[MAX_PATH * 2] = { 0 };
			FILE_DISPOSITION_INFO delete_info = { 0 };
			HANDLE h_file = INVALID_HANDLE_VALUE;

			PFILE_RENAME_INFO p_rename = nullptr;
			const wchar_t* new_stream = L":cat";

			SIZE_T stream_length = wcslen(new_stream) * sizeof(wchar_t);
			SIZE_T s_rename = sizeof(FILE_RENAME_INFO) + stream_length;

			p_rename = reinterpret_cast<PFILE_RENAME_INFO>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, s_rename));
			if (!p_rename) 
				return false;

			delete_info.DeleteFile = TRUE;
			p_rename->FileNameLength = stream_length;
			RtlCopyMemory(p_rename->FileName, new_stream, stream_length);

			if (GetModuleFileNameW(nullptr, sz_path, MAX_PATH * 2) == 0) 
				return false;

			h_file = CreateFileW(sz_path, DELETE | SYNCHRONIZE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, NULL, nullptr);
			if (h_file == INVALID_HANDLE_VALUE) 
				return false;

			if (!SetFileInformationByHandle(h_file, FileRenameInfo, p_rename, s_rename)) 
				return false;

			CloseHandle(h_file);

			h_file = CreateFileW(sz_path, DELETE | SYNCHRONIZE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, NULL, nullptr);
			if (h_file == INVALID_HANDLE_VALUE) 
				return false;

			if (!SetFileInformationByHandle(h_file, FileDispositionInfo, &delete_info, sizeof(delete_info)))
				return false;

			CloseHandle(h_file);

			HeapFree(GetProcessHeap(), 0, p_rename);

			return true;
		}
};
