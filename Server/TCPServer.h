#pragma once
#include "../includes.h"

namespace Server {

	enum Status {
		Success,
		Error,
		Unknown
	};

	enum Connection {
		Closed,
		Open
	};

	class Network {
	public:

		template <typename T>
		Status send(SOCKET, T*, std::size_t, int);

		template<typename T>
		void send(SOCKET, T*, std::size_t);

		template <typename T>
		Status recv(SOCKET, T*, std::size_t, int);

		template <typename T>
		void recv(SOCKET, T*, std::size_t);

		Status shutdown(SOCKET);

		Status close(SOCKET);

		virtual Status set_status(Connection) = 0;
	};

	class TCPServer final : public Network {
	private:
		SOCKET m_server{ INVALID_SOCKET };
		addrinfo* m_result{ nullptr };
		addrinfo m_hints{};
		WSADATA m_wsadata{};
		const char* m_port{};
		Connection m_status{ Open };

	public:
		explicit TCPServer(const char*) noexcept;

		~TCPServer() noexcept;

		Status init();

		Connection status();

		SOCKET accept();

		Status listen();

		Status set_status(Connection) override;
	};

	template <typename T>
	Status Network::send(SOCKET sock, T* buffer, std::size_t size, int flags) {

		if (::send(sock, reinterpret_cast<const char*>(buffer), static_cast<int>(size), flags) == SOCKET_ERROR) {
			return Status::Error;
		}

		return Status::Success;
	}

	template <typename T>
	Status Network::recv(SOCKET sock, T* buffer, std::size_t size, int flags) {

		int bytes_read{0};

		while (bytes_read != size) {

			bytes_read +=::recv(sock, reinterpret_cast<char*>(buffer) + bytes_read, static_cast<int>(size) - bytes_read, flags);

			if (bytes_read == SOCKET_ERROR || bytes_read == NULL)
				return Status::Error;
		}

		return Status::Success;
	}

	template<typename T>
	void Network::send(SOCKET socket, T* buffer, std::size_t size)
	{
		if (send(socket, buffer, size, NULL) != Server::Success)
			throw std::runtime_error("Failed to send data");
	}

	template<typename T>
	void Network::recv(SOCKET socket, T* buffer, std::size_t size)
	{
		if (recv(socket, buffer, size, NULL) != Server::Success)
			throw std::runtime_error("Failed to receive data");
	}

}
