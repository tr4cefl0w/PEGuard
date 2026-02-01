#pragma once
#include "../../includes.h"
#include <capstone/capstone.h>

#define MAGIC 0x5A4D

namespace PE {

	struct Import_t {
		const char* m_module{};
		const char* m_import{};
		std::uintptr_t* m_piat{}; //ignore
	};

	struct Section {
		const char* m_name{};
		DWORD m_va{};
		DWORD m_vsize{};
		DWORD m_sizeraw{};
		DWORD m_prawdata{};
		DWORD m_characteristics{};
	};

	struct Relocation {
		WORD m_type{};
		WORD m_offset{};
		DWORD m_rva{};
	};

	class PEWrapper {
	private:
		std::vector<char> m_pe{};

	public:

		explicit PEWrapper(const std::vector<char>&);

		std::uintptr_t base() const;

		_IMAGE_DOS_HEADER* dos_header() const;

		_IMAGE_NT_HEADERS* nt_header() const;

		_IMAGE_OPTIONAL_HEADER64* optional_header() const;

		_IMAGE_FILE_HEADER* file_header() const;

		_IMAGE_SECTION_HEADER* section() const; //first section after optional header

		void imports(const std::function<void(Import_t&)>&) const;

		void sections(const std::function<void(Section&)>&) const;

		void relocations(const std::function<void(Relocation&)>&) const;

		void dism(const std::function<void(cs_insn&)>&) const;

		const std::vector<char>& get_image() const;

		bool is_valid() const;

		std::map<std::uint32_t, std::pair<std::uint32_t, std::uint8_t>>  enc_regions{}; //start rva (function) is our key to get the END rva + decryption key

		std::map<std::uintptr_t*, const char*> imp_calls{}; //maps call addresses to imports 

		std::map<std::uintptr_t, std::uintptr_t> veh_calls{}; //maps call addresses to imports 

		std::list<std::tuple<std::uint32_t, std::uint32_t, std::uint8_t, bool>> rdata_chunks{};

		void strip_info();

	};
}