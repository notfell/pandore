#pragma once

extern "C" void HellsGate(DWORD wSystemCall);
extern "C" DWORD HellDescent(...);

class hellsgate : public singleton<hellsgate>
{
	public:
		BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) 
		{
			PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
			PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
			PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

			for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
				PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
				PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

				if (rt_hashing(pczFunctionName) == pVxTableEntry->dwHash)
				{
					pVxTableEntry->pAddress = pFunctionAddress;

					// Quick and dirty fix in case the function has been hooked
					WORD cw = 0;
					while (TRUE) {
						// check if syscall, in this case we are too far
						if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
							return FALSE;

						// check if ret, in this case we are also probaly too far
						if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
							return FALSE;

						// First opcodes should be :
						//    MOV R10, RCX
						//    MOV RCX, <syscall>
						if (*((PBYTE)pFunctionAddress + cw) == 0x4c
							&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
							&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
							&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
							&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
							&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
							BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
							BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
							pVxTableEntry->wSystemCall = (high << 8) | low;
							std::cout << AY_OBFUSCATE("+ syscall found : ") << pczFunctionName << AY_OBFUSCATE("(0x") << rt_hashing(pczFunctionName) << AY_OBFUSCATE(")") << AY_OBFUSCATE("| ssn : ") << std::dec << pVxTableEntry->wSystemCall << std::endl;
							break;
						}

						cw++;
					};
				}
			}

			return TRUE;
		}
};