#pragma once

#define PEGUARD_API __declspec(dllexport)

struct RUNTIME_CONTROL
{
	
};

extern "C" {
	PEGUARD_API int PEGuard_Integrity();
	PEGUARD_API int PEGuard_Encrypt_Start();
	PEGUARD_API int PEGuard_Encrypt_End();
}

#define CHECK_INTEGRITY PEGuard_Integrity();
#define ENC_START PEGuard_Encrypt_Start();
#define ENC_END PEGuard_Encrypt_End();