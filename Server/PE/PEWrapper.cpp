#include "PEWrapper.h"

namespace PE {

	PEWrapper::PEWrapper(const std::vector<char>& unmapped_pe) { //implement exceptions

		auto dosheader = (IMAGE_DOS_HEADER*)unmapped_pe.data();

		auto ntheader = (IMAGE_NT_HEADERS*)(unmapped_pe.data() + dosheader->e_lfanew);

		m_pe.resize(ntheader->OptionalHeader.SizeOfImage, 0);

		std::memcpy(m_pe.data(), unmapped_pe.data(), 0x1000); //copy headers over

		std::for_each_n(section(), file_header()->NumberOfSections, [&](const auto& sec_header)
		{
			std::memcpy(m_pe.data() + sec_header.VirtualAddress, unmapped_pe.data() + sec_header.PointerToRawData, std::min(sec_header.Misc.VirtualSize, sec_header.SizeOfRawData)); //hmmm
		});
	}

	std::uintptr_t PEWrapper::base() const {
		return (std::uintptr_t)m_pe.data();
	}

	_IMAGE_DOS_HEADER* PEWrapper::dos_header() const {
		return (_IMAGE_DOS_HEADER*)base();
	}

	_IMAGE_NT_HEADERS* PEWrapper::nt_header() const {
		return (_IMAGE_NT_HEADERS*)(base() + dos_header()->e_lfanew);
	}

	_IMAGE_OPTIONAL_HEADER64* PEWrapper::optional_header() const {
		return (_IMAGE_OPTIONAL_HEADER64*)&nt_header()->OptionalHeader;
	}

	_IMAGE_FILE_HEADER* PEWrapper::file_header() const {
		return (_IMAGE_FILE_HEADER*)&nt_header()->FileHeader;
	}

	_IMAGE_SECTION_HEADER* PEWrapper::section() const {
		return IMAGE_FIRST_SECTION(nt_header());
	}

	void PEWrapper::imports(const std::function<void(Import_t&)>& func) const {

		Import_t data{};

		auto desc = (_IMAGE_IMPORT_DESCRIPTOR*)(base() + optional_header()->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		for (; desc->Name != NULL; ++desc) {

			data.m_module = (char*)(base() + desc->Name);

			auto oftthunk = (_IMAGE_THUNK_DATA64*)(base() + desc->OriginalFirstThunk);

			auto firstthunk = (_IMAGE_THUNK_DATA64*)(base() + desc->FirstThunk);

			for (; oftthunk->u1.AddressOfData != NULL; ++oftthunk, ++firstthunk) {

				data.m_import = ((_IMAGE_IMPORT_BY_NAME*)(base() + oftthunk->u1.AddressOfData))->Name;
				data.m_piat = &firstthunk->u1.Function;

				func(data);
			}
		}
	}

	void PEWrapper::sections(const std::function<void(Section&)>& func) const {

		Section data{};

		std::for_each_n(section(), file_header()->NumberOfSections, [&](const auto& sec_header)
		{
			data.m_name = (char*)sec_header.Name;
			data.m_va = sec_header.VirtualAddress;
			data.m_vsize = sec_header.Misc.VirtualSize;
			data.m_sizeraw= sec_header.SizeOfRawData;
			data.m_prawdata = sec_header.PointerToRawData;
			data.m_characteristics = sec_header.Characteristics;

			func(data);
		});
	}

	void PEWrapper::relocations(const std::function<void(Relocation&)>& func) const { //shitty but works

		Relocation data{};

		auto desc = (_IMAGE_BASE_RELOCATION*)(base() + optional_header()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (desc->SizeOfBlock) {

			DWORD count = (desc->SizeOfBlock - sizeof(_IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			WORD* entries = (WORD*)(desc + 1);

			for (DWORD i = 0; i < count; i++) {
				WORD type = entries[i] >> 12; //high 4 bits
				WORD offset = entries[i] & 0xFFF; //low 12 bits

				data.m_rva = desc->VirtualAddress;
				data.m_type = type;
				data.m_offset = offset;

				func(data);
			}

			desc = (_IMAGE_BASE_RELOCATION*)((BYTE*)desc + desc->SizeOfBlock);
		}
	}

	void PEWrapper::dism(const std::function<void(cs_insn&)>& func) const
	{
		csh handle;
		cs_insn* insn;

		cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
		if (err != CS_ERR_OK) {
			printf("cs_open failed: %s\n", cs_strerror(err));
			return;
		}

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		std::size_t count = cs_disasm(handle, (std::uint8_t*)(base() + section()->VirtualAddress), section()->Misc.VirtualSize, base() + section()->VirtualAddress, 0, &insn);
		if (count > 0) {
			size_t j;

			for (j = 0; j < count; j++) {

				cs_x86* x86 = &insn[j].detail->x86;

				if (x86->op_count == 1)
				{
					cs_x86_op& op = x86->operands[0];

					if (op.type == X86_OP_MEM && op.size == 8)
					{
						func(insn[j]);
					}
				}
			}

			cs_free(insn, count);
		}

		cs_close(&handle);
	}

	void PEWrapper::strip_info()
	{
		sections([&](Section& sec)
		{
			if (std::strcmp(sec.m_name, ".reloc") == 0 || std::strcmp(sec.m_name, ".rsrc") == 0)
			{
				std::fill_n(m_pe.data() + sec.m_va, sec.m_vsize, 0);
			}
		});

		imports([&](Import_t import)
		{
			std::fill_n(const_cast<char*>(import.m_module), std::strlen(import.m_import), 0); //bruh
			std::fill_n(const_cast<char*>(import.m_import), std::strlen(import.m_import), 0);
			//theres more to it
		});

		std::fill_n(m_pe.data(), optional_header()->SizeOfHeaders, 0);
	}

	bool PEWrapper::is_valid() const {
		return dos_header()->e_magic == MAGIC;
	}

	const std::vector<char>& PEWrapper::get_image() const {
		return m_pe;
	}
}