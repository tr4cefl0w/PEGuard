#include "../includes.h"
#include "TCPClient.h"
#include "Runtime.hpp"

using net = std::unique_ptr<Client::TCPClient>;
using pkt = std::unique_ptr<Packet_t>;

static Client::Status client_alloc()
{
	icb.image_base = reinterpret_cast<std::uintptr_t>(VirtualAlloc(nullptr, icb.size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS));

	if (icb.image_base == NULL)
	{
		return Client::Error;
	}

	return Client::Success;
}

static Client::Status client_imports(std::string& imports_data)
{
	json data = json::parse(imports_data);

	for (const auto& [module, imports] : data.items())
	{
		for (auto& [imp, addr] : imports.items())
		{
			HMODULE dll = GetModuleHandleA(module.c_str());

			if (dll == nullptr) {
				dll = LoadLibraryA(module.c_str());
			}

			addr = reinterpret_cast<std::uintptr_t>(GetProcAddress(dll, imp.c_str()));

			//spdlog::info("Module: {} -> Import {} -> Address {:#x}", module, imp, addr.get<std::uintptr_t>());
		}
	}

	imports_data = data.dump();

	return Client::Success;
}

static Client::Status client_map(const std::vector<char>& image, const std::string& sections)
{
	//AddVectoredExceptionHandler(1, Runtime::IAT_Handler_Direct);

	Runtime::HookNtdll();

	json data = json::parse(sections);

	for (const auto& section : data) //kinda useless, unless wanna set proper section protections
	{
		VirtualAlloc((BYTE*)icb.image_base + section[0].get<DWORD>(), ALIGN_UP(section[1].get<DWORD>(), 0x1000), MEM_COMMIT, PAGE_EXECUTE_READWRITE); //hmm?

		std::memcpy((BYTE*)icb.image_base + section[0].get<DWORD>(), image.data() + section[0].get<DWORD>(), section[1].get<DWORD>());
	}

	spdlog::info("Mapped PE into {:#x}", icb.image_base);

	DWORD old{};

	VirtualProtect((std::uint8_t*)(icb.image_base + 0x2000), 0x1000, PAGE_READWRITE | PAGE_GUARD, &old);

	std::invoke(reinterpret_cast<void(*)()>(icb.image_base + icb.oep));

	return Client::Success;
}

static Client::Status run_client(net& client)
{
	auto packet = std::make_unique<Packet_t>();

	client->send(packet.get(), p_size);
	
	client->recv(packet.get(), p_size);

	icb.size_of_image = packet->m_data.m_init.size_of_image;
	icb.oep = packet->m_data.m_init.entry_point;

	Client::Status state = client_alloc();

	if (state != Client::Success)
	{
		return Client::Error;
	}

	packet->m_stage = Packet_t::ALLOC;
	packet->m_data.m_alloc.image_base = icb.image_base;

	client->send(packet.get(), p_size);

	packet->m_stage = Packet_t::IMPORTS;
	packet->m_data.m_imports.integrity_handler = reinterpret_cast<std::uintptr_t>(&Runtime::PEGuard_Integrity);
	packet->m_data.m_imports.encrypt_handler = reinterpret_cast<std::uintptr_t>(&Runtime::PEGuard_Encrypt_Start);
	packet->m_data.m_imports.reencrypt_handler = reinterpret_cast<std::uintptr_t>(&Runtime::PEGuard_Encrypt_End);

	client->send(packet.get(), p_size);

	client->recv(packet.get(), p_size);

	std::string buffer;
	buffer.resize(packet->m_data.m_imports.size_of_packet, 0);

	client->recv(buffer.data(), buffer.size());

	state = client_imports(buffer);

	if (state != Client::Success)
	{
		return Client::Error;
	}

	packet->m_data.m_imports.size_of_packet = buffer.size();

	client->send(packet.get(), p_size);
		
	client->send(buffer.data(), buffer.size());

	packet->m_stage = Packet_t::IMAGE;

	client->send(packet.get(), p_size);

	std::vector<char> file(icb.size_of_image);

	client->recv(file.data(), file.size());

	client->recv(packet.get(), p_size);

	buffer.resize(packet->m_data.m_image.size_of_packet, 0);

	client->recv(buffer.data(), buffer.size());

	Runtime::icb_client = std::move(client);
	Runtime::icb_packet = std::move(packet);

	state = client_map(file, buffer);

	if (state != Client::Success)
	{
		return Client::Error;
	}

	return Client::Success;
}

int main()
{
	auto client = std::make_unique<Client::TCPClient>(IPV4, PORT);

	if (client->init() != Client::Success)
	{
		spdlog::error("Client failed with code: {}", client->get_error());
		return EXIT_FAILURE;
	}
		
	if (client->establish() != Client::Success)
	{
		spdlog::error("Client failed with code: {}", client->get_error());
		return EXIT_FAILURE;
	}

	try {

		Client::Status state = run_client(client);

		if (state != Client::Success)
		{
			return EXIT_FAILURE;
		}
	}
	catch (std::exception& e)
	{
		spdlog::error(e.what());
	}

	return EXIT_SUCCESS;
}