#include "injector.hpp"

int main(void)
{
	Injector = std::make_unique<CInjector>();
	
	PVOID Bytes{};
	SIZE_T Size{};

	if (!Injector->LoadFileIntoMemory(L"module.dll", Bytes, Size))
	{
		printf("module.dll was not found in executable directory\n");
		return -1;
	}
		
	Sleep(500);

	Injector->Attach(L"notepad.exe");
	
	if (!Injector->MapDll(Bytes, Size, true))
	{
		printf("failed to inject dll \n");
	}
	else
	{
		printf("injected dll \n");
	}
	
	Injector->Detach();

	free(Bytes);


	std::cin.get();

	return 0;
}
