#pragma once
#include "../includes.h"

namespace Client {

	enum Status {
		Success,
		Error,
		Unknown
	};

	class TCPClient
	{
	private:
		const char* m_ipv4{};
		const char* m_port{};

		WSADATA m_wsaData{};
		SOCKET m_connection{};
		addrinfo m_info{};
		addrinfo* m_result{};

	public:

		TCPClient(const char* ipv4, const char* port)
			: m_ipv4{ ipv4 }, m_port{ port }
		{

		}

		Status init();

		Status establish();

		std::int32_t get_error();

		template <typename T>
		Status send(T*, std::size_t, int);

		template<typename T>
		void send(T*, std::size_t);

		template <typename T>
		Status recv(T*, std::size_t, int);

		template <typename T>
		void recv(T*, std::size_t);
	};

	template <typename T>
	Status TCPClient::send(T* buffer, std::size_t size, int flags) {

		if (::send(m_connection, reinterpret_cast<const char*>(buffer), static_cast<int>(size), flags) == SOCKET_ERROR) {
			return Status::Error;
		}

		return Status::Success;
	}

	template <typename T>
	Status TCPClient::recv(T* buffer, std::size_t size, int flags) {

		int bytes_read{ 0 };

		while (bytes_read != size) {

			bytes_read += ::recv(m_connection, reinterpret_cast<char*>(buffer) + bytes_read, static_cast<int>(size) - bytes_read, flags);

			if (bytes_read == SOCKET_ERROR || bytes_read == NULL)
				return Status::Error;
		}

		return Status::Success;
	}

	template<typename T>
	void TCPClient::send(T* buffer, std::size_t size)
	{
		if (send(buffer, size, NULL) != Client::Success)
			throw std::runtime_error("Failed to send data");
	}

	template<typename T>
	void TCPClient::recv(T* buffer, std::size_t size)
	{
		if (recv(buffer, size, NULL) != Client::Success)
			throw std::runtime_error("Failed to receive data");
	}

}