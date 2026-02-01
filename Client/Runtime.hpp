#pragma once
#include "TCPClient.h"
#include "../includes.h"
#include "inline_syscall.hpp"

struct IMAGE_CONTROL_BLOCK {
	std::uintptr_t image_base{};
	std::size_t size_of_image{};
	std::uint32_t oep{};
	std::map<std::uint32_t, std::uint32_t> function_table{}; //end rva, start rva, key
};

static IMAGE_CONTROL_BLOCK icb;

EXTERN_C NTSTATUS NTAPI NtContinue(
	_In_ PCONTEXT ContextRecord,
	_In_ BOOLEAN TestAlert
);

namespace Runtime {

	inline std::unique_ptr<Client::TCPClient> icb_client;
	inline std::unique_ptr<Packet_t> icb_packet;

	extern "C" {

		inline int PEGuard_Integrity()
		{
			return -1;
		}

		[[maybe_unused]]
		int PEGuard_Encrypt_Start()
		{
			icb_packet->m_stage = Packet_t::DEC_REGION;

			icb_packet->m_data.m_region.start_rva = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(_ReturnAddress()) - icb.image_base);

			if (icb_client->send(icb_packet.get(), p_size, NULL) != Client::Success)
			{
				return Client::Error;
			}

			if (icb_client->recv(icb_packet.get(), p_size, NULL) != Client::Success)
			{
				return Client::Error;
			}

			std::uint32_t count = icb_packet->m_data.m_region.end_rva - icb_packet->m_data.m_region.start_rva;

			std::for_each_n((std::uint8_t*)(icb.image_base + icb_packet->m_data.m_region.start_rva), count, [&](std::uint8_t& byte)
			{
				byte ^= icb_packet->m_data.m_region.key;
			});

			icb.function_table[icb_packet->m_data.m_region.end_rva] = icb_packet->m_data.m_region.start_rva;

			return Client::Success;

		}

		[[maybe_unused]]
		int PEGuard_Encrypt_End()
		{
			auto found = icb.function_table.find(static_cast<std::uint32_t>((reinterpret_cast<std::uintptr_t>(_ReturnAddress())) - icb.image_base));

			if (found != icb.function_table.end())
			{
				std::uint32_t count = found->first - found->second;

				std::for_each_n((std::uint8_t*)(icb.image_base + found->second), count, [&](std::uint8_t& byte)
				{
					byte ^= 0x90; //u can gen a random value here
				});

				return Client::Success;
			}

			return Client::Error;
		}
	}


	//inline to shut up resharper
	[[maybe_unused]]
	inline LONG IAT_Handler(_EXCEPTION_POINTERS* ExceptionInfo)
	{
		if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
		{
			icb_packet->m_stage = Packet_t::VEH;

			std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(ExceptionInfo->ExceptionRecord->ExceptionAddress);

			std::uintptr_t dest = addr + 6 + *(std::int32_t*)(addr + 2);

			icb_packet->m_data.m_veh.m_info.faulty_address = dest - icb.image_base;

			if (icb_client->send(icb_packet.get(), p_size, NULL) != Client::Success)
			{
				return Client::Error;
			}

			if (icb_client->recv(icb_packet.get(), p_size, NULL) != Client::Success)
			{
				return Client::Error;
			}

			*(std::uintptr_t*)dest = icb_packet->m_data.m_veh.m_info.fixed_address;

			return EXCEPTION_CONTINUE_EXECUTION;
		}

		return EXCEPTION_CONTINUE_SEARCH;
	}

	[[maybe_unused]]
	inline LONG IAT_Handler_Direct(_EXCEPTION_POINTERS* ExceptionInfo)
	{
		if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
		{
			icb_packet->m_stage = Packet_t::VEH;

			icb_packet->m_data.m_veh.m_info.faulty_address = reinterpret_cast<std::uintptr_t>(ExceptionInfo->ExceptionRecord->ExceptionAddress);

			if (icb_client->send(icb_packet.get(), p_size, NULL) != Client::Success)
			{
				return Client::Error;
			}

			if (icb_client->recv(icb_packet.get(), p_size, NULL) != Client::Success)
			{
				return Client::Error;
			}

			ExceptionInfo->ContextRecord->Rip = icb_packet->m_data.m_veh.m_info.fixed_address;

			return EXCEPTION_CONTINUE_EXECUTION;
		}

		return EXCEPTION_CONTINUE_SEARCH;
	}

	static inline_syscall inliner;

	[[maybe_unused]]
	inline LONG IAT_Handler_Hook(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ContextRecord)
	{
		if (ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		{
			icb_packet->m_stage = Packet_t::DATA;

			icb_packet->m_data.m_rdata.m_info.accessed_address = static_cast<std::uint32_t>(ExceptionRecord->ExceptionInformation[1] - icb.image_base);

			if (icb_client->send(icb_packet.get(), p_size, NULL) != Client::Success)
			{
				return Client::Error;
			}

			if (icb_client->recv(icb_packet.get(), p_size, NULL) != Client::Success)
			{
				return Client::Error;
			}

			ContextRecord->EFlags |= 0x100; // TF

			if (icb_packet->m_data.m_rdata.m_info.resp.already_decrypted)
			{
				NtContinue(ContextRecord, false);
			}

			std::for_each_n((std::uint8_t*)(icb.image_base + icb_packet->m_data.m_rdata.m_info.resp.start_address), 64, [&](std::uint8_t& byte)
			{
				byte ^= icb_packet->m_data.m_rdata.m_info.resp.key;
			});
		}

		if (ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
		{
			DWORD old{};

			VirtualProtect((std::uint8_t*)(icb.image_base + 0x2000), 0x1000, PAGE_READWRITE | PAGE_GUARD, &old);

			ContextRecord->EFlags &= ~0x100;
		}

		if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
		{
			icb_packet->m_stage = Packet_t::VEH;

			icb_packet->m_data.m_veh.m_info.faulty_address = reinterpret_cast<std::uintptr_t>(ExceptionRecord->ExceptionAddress);

			if (icb_client->send(icb_packet.get(), p_size, NULL) != Client::Success)
			{
				return Client::Error;
			}

			if (icb_client->recv(icb_packet.get(), p_size, NULL) != Client::Success)
			{
				return Client::Error;
			}

			ContextRecord->Rip = icb_packet->m_data.m_veh.m_info.fixed_address;
		}

		if (inliner.is_init())
		{
			inliner.invoke<NTSTATUS>("NtContinue", ContextRecord, FALSE);
		}

		NtContinue(ContextRecord, FALSE);

		return Client::Success;
	}

	[[maybe_unused]]
	inline void HookNtdll() 
	{
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");

		DWORD old{};

		VirtualProtect((std::uint8_t*)ntdll + 0x181230, sizeof(std::uintptr_t), PAGE_READWRITE, &old);

		*(std::uintptr_t*)((std::uint8_t*)ntdll + 0x181230) = reinterpret_cast<std::uintptr_t>(&IAT_Handler_Hook);

		VirtualProtect((std::uint8_t*)ntdll + 0x181230, sizeof(std::uintptr_t), PAGE_READONLY, &old);

	} 

}