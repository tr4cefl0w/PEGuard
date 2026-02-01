#pragma once
#include <iostream>
#include <variant>
#include <vector>
#include <memory>
#include <thread>
#include <cstdint>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <WinSock2.h>
#include <ws2tcpip.h>

#include <Windows.h>
#include <random>
#include <winternl.h>
#include <algorithm>
#include <fstream>
#include <functional>

#pragma comment (lib, "Ws2_32.lib")

#define PORT "1337"
#define IPV4 "127.0.0.1"

struct Packet_t
{
	enum Stage_t : std::uint8_t
	{
		INIT,
		ALLOC,
		IMPORTS,
		IMAGE,
		DEC_REGION,
		VEH,
		DATA
	};

	Stage_t m_stage{};

	struct Init_t
	{
		std::size_t size_of_image{};
		std::uint32_t entry_point{};
	};

	struct Alloc_t
	{
		std::uintptr_t image_base{};
	};

	struct Imports_t
	{
		std::size_t size_of_packet{}; //actual bytes -> vector.size() * sizeof(imports)
		std::uintptr_t integrity_handler{};
		std::uintptr_t encrypt_handler{};
		std::uintptr_t reencrypt_handler{};
	};

	struct Image_t
	{
		std::size_t size_of_packet{};
	};

	struct Region_t
	{
		std::uint32_t start_rva{};
		std::uint32_t end_rva{};
		std::uint8_t key{};
	};

	struct Data_t
	{
		union
		{
			std::uint32_t accessed_address; //rva to accessed address inside .rdata
			
			struct Resp
			{
				std::uint32_t start_address{}; //rva to start of chunk
				std::uint8_t key;
				bool already_decrypted{ false };
			} resp;

		} m_info;
	};

	struct Veh_t
	{
		union
		{
			std::uintptr_t faulty_address; //an rva now
			std::uintptr_t fixed_address;
		} m_info;
	};

	union
	{
		Init_t m_init;
		Alloc_t m_alloc;
		Imports_t m_imports;
		Image_t m_image;
		Region_t m_region;
		Veh_t m_veh;
		Data_t m_rdata;

	} m_data;

	Packet_t()
		: m_stage{ INIT }, m_data{}
	{

	}
};

constexpr std::size_t p_size = sizeof(Packet_t);

using json = nlohmann::json;

#define ALIGN_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

constexpr std::array veh_imports_list = { "MessageBoxA", "GetSystemTimeAsFileTime", "QueryPerformanceCounter", "GetCurrentThreadId", "GetCurrentProcessId" , "PEGuard_Encrypt_Start"};