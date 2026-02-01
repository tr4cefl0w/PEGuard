#include "../includes.h"
#include "TCPServer.h"
#include "PE/PEWrapper.h"
#include "utils.h"

using net = std::shared_ptr<Server::Network>;
using img = std::unique_ptr<PE::PEWrapper>;
using pkt = std::unique_ptr<Packet_t>;

static void handle_init(SOCKET socket, net& network, img& image, pkt& packet)
{
	packet->m_data.m_init.size_of_image = image->optional_header()->SizeOfImage;
	packet->m_data.m_init.entry_point = image->optional_header()->AddressOfEntryPoint;

	network->send(socket, packet.get(), p_size);
}

static void handle_imports(SOCKET socket, net& network, img& image, pkt& packet)
{
	json data{};

	image->imports([&](PE::Import_t& imp)
	{
		if (strcmp(imp.m_module, "PEGuard.dll") == 0) { //dont process our Exports
			image->imp_calls[imp.m_piat] = imp.m_import;
			return;
		}

		data[imp.m_module][imp.m_import] = nullptr;
	});

	std::uint32_t start_reg{};

	image->dism([&](cs_insn& inst)
	{
		std::uintptr_t* dest = (std::uintptr_t*)(inst.address + inst.size + inst.detail->x86.disp);

		auto found = image->imp_calls.find(dest);

		if (found != image->imp_calls.end())
		{
			if (strcmp(found->second, "PEGuard_Encrypt_Start") == 0)
			{
				start_reg = static_cast<std::uint32_t>((inst.address + inst.size) - image->base()); //cast to shut up compiler warnings
			}

			if (strcmp(found->second, "PEGuard_Encrypt_End") == 0)
			{
				image->enc_regions[start_reg] = std::make_pair(static_cast<std::uint32_t>((inst.address + inst.size) - image->base()), gen_key()); //address + size cuz we want to encrypt the call to PEGuard_Encrypt_End 
			}
		}
	});

	for (const auto& [start_rva, info] : image->enc_regions)
	{
		std::size_t count = info.first - start_rva;

		std::for_each_n((std::uint8_t*)(image->base() + start_rva), count, [&](std::uint8_t& byte)
		{
			byte ^= info.second; //second = key
		});
	}

	std::string buffer{ data.dump() };

	packet->m_data.m_imports.size_of_packet = buffer.size();

	network->send(socket, packet.get(), p_size);

	network->send(socket, buffer.data(), buffer.size());

	network->recv(socket, packet.get(), p_size);

	buffer.resize(packet->m_data.m_imports.size_of_packet);

	network->recv(socket, buffer.data(), buffer.size());

	data = json::parse(buffer);

	int count{ 0 };

	image->imports([&](PE::Import_t& imp)
	{
		if (strcmp(imp.m_import, "PEGuard_Integrity") == 0) //patch import to our handler
		{
			*imp.m_piat = packet->m_data.m_imports.integrity_handler;
			return;
		}

		if (strcmp(imp.m_import, "PEGuard_Encrypt_Start") == 0) //patch import to our handler
		{
			image->veh_calls[*imp.m_piat] = packet->m_data.m_imports.encrypt_handler;
			//*imp.m_piat = packet->m_data.m_imports.encrypt_handler;
			return;
		}

		if (strcmp(imp.m_import, "PEGuard_Encrypt_End") == 0) //patch import to our handler
		{
			*imp.m_piat = packet->m_data.m_imports.reencrypt_handler;
			return;
		}

		auto mod_it = data.find(imp.m_module); //should be pretty optimized
		if (mod_it == data.end())
			return;

		auto imp_it = mod_it->find(imp.m_import);
		if (imp_it == mod_it->end())
			return;

		/*if (strcmp(imp.m_import, "MessageBoxA") == 0) 
		{
			image->veh_calls[reinterpret_cast<std::uintptr_t>(imp.m_piat) - image->base()] = imp_it->get<std::uintptr_t>();
			*imp.m_piat = gen_fake_import();
			return;
		}*/

		auto found = std::ranges::find_if(veh_imports_list, [&](const auto& it)
		{
			return std::strcmp(it, imp.m_import) == 0 ? true : false;
		});

		if (found != veh_imports_list.end())
		{
			image->veh_calls[*imp.m_piat] = imp_it->get<std::uintptr_t>();
			return;
		}

		*imp.m_piat = imp_it->get<std::uintptr_t>();

		++count;
	});

	spdlog::info("Imports have been resolved -> Count: {}", count);
}

static void handle_alloc(SOCKET socket, net& network, img& image, pkt& packet)
{
	std::uintptr_t delta = packet->m_data.m_alloc.image_base - image->optional_header()->ImageBase;

	image->relocations([&](PE::Relocation& reloc)
	{
		switch (reloc.m_type) {

		case IMAGE_REL_BASED_DIR64:
			*(std::uintptr_t*)((image->base() + reloc.m_rva) + reloc.m_offset) += delta;
			break;
		case IMAGE_REL_BASED_HIGH:
			break;
		default:
			spdlog::warn("Relocation was not handled -> Type: {}", reloc.m_type);
		}
		//etc
	});

	spdlog::info("Image has been relocated to new base: {:#x}", packet->m_data.m_alloc.image_base);
}

static void handle_image(SOCKET socket, net& network, img& image, pkt& packet)
{
	json data{};

	image->sections([&](PE::Section& sec)
	{
		data.push_back({ sec.m_va, sec.m_vsize, sec.m_characteristics });

		if (std::strcmp(sec.m_name, ".rdata") == 0)
		{
			std::size_t count = sec.m_vsize / 64;

			DWORD s_va = sec.m_va;

			for (std::size_t i{0}; i <= count; ++i, s_va += 64)
			{
				std::uint8_t key = gen_key();

				std::for_each_n((std::uint8_t*)(image->base() + s_va), 64, [&](std::uint8_t& byte)
				{
					byte ^= key;
				});

				image->rdata_chunks.emplace_back(s_va, s_va + 64, key, false);
			}
		}
	});

	std::size_t sec_count = image->file_header()->NumberOfSections;

	//image->strip_info();

	network->send(socket, image->get_image().data(), image->get_image().size());

	std::string buffer{ data.dump() };

	packet->m_data.m_image.size_of_packet = buffer.size();

	network->send(socket, packet.get(), p_size);

	network->send(socket, buffer.data(), buffer.size());

	spdlog::info("Sections have been resolved -> Count: {}", sec_count);
}

static void handle_decryption(SOCKET socket, net& network, img& image, pkt& packet)
{
	auto found = image->enc_regions.find(packet->m_data.m_region.start_rva);

	if (found != image->enc_regions.end())
	{
		packet->m_data.m_region.end_rva = found->second.first;
		packet->m_data.m_region.key = found->second.second;

		spdlog::info("Found encrypted region.");
	}

	network->send(socket, packet.get(), p_size);
}

static void handle_veh(SOCKET socket, net& network, img& image, pkt& packet)
{
	auto found = image->veh_calls.find(packet->m_data.m_veh.m_info.faulty_address);

	if (found != image->veh_calls.end())
	{
		spdlog::info("Found VEH import.");
		packet->m_data.m_veh.m_info.fixed_address = found->second;
	}

	network->send(socket, packet.get(), p_size);
}

static void handle_data_section(SOCKET socket, net& network, img& image, pkt& packet)
{
	spdlog::info("RDATA handler invoked.");

	for (auto& [start, end, key, decrypted]: image->rdata_chunks)
	{
		if (packet->m_data.m_rdata.m_info.accessed_address >= start && packet->m_data.m_rdata.m_info.accessed_address <= end)
		{
			if (decrypted)
			{
				spdlog::info("Found already decrypted RDATA chunk.");
				packet->m_data.m_rdata.m_info.resp.already_decrypted = true;
			}
			else
			{
				spdlog::info("Found RDATA chunk.");
				packet->m_data.m_rdata.m_info.resp.already_decrypted = false;
				packet->m_data.m_rdata.m_info.resp.start_address = start;
				packet->m_data.m_rdata.m_info.resp.key = key;
				decrypted = true;
			}
		}
	}

	network->send(socket, packet.get(), p_size);
}

static void client_worker(SOCKET socket, std::shared_ptr<Server::Network> network, const std::vector<char>& s_pe) {

	int ins_reads{ 0 };

	try {

		spdlog::info("Thread invoked with ID: {}", socket);

		auto packet = std::make_unique<Packet_t>();

		auto image = std::make_unique<PE::PEWrapper>(s_pe);

		while (network->recv(socket, packet.get(), p_size, NULL) != Server::Status::Error)
		{
			switch (packet->m_stage)
			{
			case Packet_t::INIT:
				handle_init(socket, network, image, packet);
				break;
			case Packet_t::ALLOC:
				handle_alloc(socket, network, image, packet);
				break;
			case Packet_t::IMPORTS:
				handle_imports(socket, network, image, packet);
				break;
			case Packet_t::IMAGE:
				handle_image(socket, network, image, packet);
				break;
			case Packet_t::DEC_REGION:
				handle_decryption(socket, network, image, packet);
				break;
			case Packet_t::VEH:
				handle_veh(socket, network, image, packet);
				break;
			case Packet_t::DATA:
				handle_data_section(socket, network, image, packet);
				++ins_reads;
				break;
			}
		}
	}
	catch (std::exception& e)
	{
		network->shutdown(socket);
		network->close(socket);
		spdlog::error(e.what());
	}

	network->shutdown(socket);
	network->close(socket);

	spdlog::info("Total of {} Reads from .rdata section", ins_reads);
}

int main() {

	auto server = std::make_shared<Server::TCPServer>(PORT); //listening port

	std::vector<char> m_pe = parse_file("Dummy.exe");

	if (server->init() != Server::Status::Success)
		return EXIT_FAILURE;

	if (server->listen() != Server::Status::Success)
		return EXIT_FAILURE;

	spdlog::info("Server is listening on port -> {}", PORT);

	while (server->status()) {

		SOCKET sock = server->accept();

		if (sock == INVALID_SOCKET)
			continue;

		std::thread(client_worker, sock, server, m_pe).detach();
	}
}