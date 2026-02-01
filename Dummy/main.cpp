#include <iostream>
#include <Windows.h>

#include "PEGuard/PEGuard.h"

__declspec(noinline)
void dummy1()
{
	ENC_START

	int ret = MessageBoxA(nullptr, "Another Dummy called", "PEGuard", NULL);

	ENC_END //wont reencrypt 
}

__declspec(noinline)
void dummy()
{
	ENC_START

	int ret = MessageBoxA(nullptr, "Dummy called", "PEGuard", NULL);

	ENC_END

	dummy1();
}

int main()
{
	ENC_START

	CHECK_INTEGRITY

	int ret = MessageBoxA(nullptr, "I am protected", "PEGuard", NULL);

	dummy();

	ENC_END

	return ret;
}