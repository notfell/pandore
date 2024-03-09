#include "vendor.h"

auto main() -> int
{
	printf(AY_OBFUSCATE("+ pandore v0.1\n"));

	if (protect::get()->run())
	{
		if (!app::get()->retrieve())
		{
			printf(AY_OBFUSCATE("\n+ retrieve() failed\n"));
			return EXIT_FAILURE;
		}

		printf(AY_OBFUSCATE("\n+ retrieve() success\n"));

		if (!app::get()->invoke())
		{
			printf(AY_OBFUSCATE("- invoke() failed\n"));
			return EXIT_FAILURE;
		}

		printf(AY_OBFUSCATE("+ invoke() success\n"));

		if (!app::get()->write(&vx_table))
		{
			printf(AY_OBFUSCATE("- write() failed\n"));
			return EXIT_FAILURE;
		}

		printf(AY_OBFUSCATE("+ write() success\n"));

		if (!app::get()->run(&vx_table))
		{
			printf(AY_OBFUSCATE("- run() failed\n"));
			return EXIT_FAILURE;
		}

		printf(AY_OBFUSCATE("+ run() success\n"));
		printf(AY_OBFUSCATE("+ pandore | github.com/notfell\n"));
	}

	utils::get()->self_delete();

	return (EXIT_SUCCESS);
}