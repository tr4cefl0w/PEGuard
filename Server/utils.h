#pragma once
#include "../includes.h"

inline std::vector<char> parse_file(const char* file_name) {

	std::ifstream input{ file_name , std::ios::binary };

	if (!input.good()) {
		throw std::runtime_error("Failed to open file");
	}

	return { std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>() };
}

inline std::mt19937_64 mt{ std::random_device{}() };

inline std::uint8_t gen_key()
{
	return mt() % 256;
}

inline std::uintptr_t gen_fake_import()
{
	return mt();
}