#pragma once

#define seed 10

constexpr int rdn_ct_seed(void)
{
	return '0' * -40271 + __TIME__[7] * 1 + __TIME__[6] * 10 + __TIME__[4] * 60 + __TIME__[3] * 600 + __TIME__[1] * 3600 + __TIME__[0] * 36000;
};

constexpr auto g_ct_key = rdn_ct_seed() % 0xFF;

constexpr DWORD djb2a_hashing(const char* _string)
{
	ULONG hash = (ULONG)g_ct_key;
	INT c = 0;
	while ((c = *_string++))
	{
		hash = ((hash << seed) + hash) + c;
	}

	return hash;
}

#define rt_hashing( funct ) djb2a_hashing((const char*) funct) //runtime hashing
#define ct_hashing( funct ) constexpr auto my_##funct = djb2a_hashing((const char*) #funct); //compile time hashing funct
#define ct_module_hashing( module_name ) constexpr auto my_##module_name = djb2a_hashing((const char*) module_name);
