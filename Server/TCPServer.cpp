#include "TCPServer.h"

namespace Server {

	TCPServer::TCPServer(const char* port) noexcept
		: m_port{ port }
	{

	}

	TCPServer::~TCPServer() {
		WSACleanup();
		closesocket(m_server);
	}

	Status TCPServer::init() {

		if (WSAStartup(MAKEWORD(2, 2), &m_wsadata) != 0) {
			return Status::Error;
		}

		ZeroMemory(&m_hints, sizeof(m_hints));
		m_hints.ai_family = AF_INET;
		m_hints.ai_socktype = SOCK_STREAM;
		m_hints.ai_protocol = IPPROTO_TCP;
		m_hints.ai_flags = AI_PASSIVE;

		if (getaddrinfo(NULL, m_port, &m_hints, &m_result) != 0) {
			return Status::Error;
		}

		m_server = socket(m_result->ai_family, m_result->ai_socktype, m_result->ai_protocol);

		if (m_server == INVALID_SOCKET) {
			return Status::Error;
		}

		if (bind(m_server, m_result->ai_addr, (int)m_result->ai_addrlen) == SOCKET_ERROR) {
			return Status::Error;
		}

		freeaddrinfo(m_result);

		return Status::Success;
	}

	Connection TCPServer::status() {
		return m_status;
	}

	Status TCPServer::set_status(Connection status) {
		m_status = status;
		return Status::Success;
	}

	SOCKET TCPServer::accept() {
		return ::accept(m_server, NULL, NULL);
	}

	Status TCPServer::listen() {

		if (::listen(m_server, SOMAXCONN) == INVALID_SOCKET) {
			return Status::Error;
		}

		return Status::Success;
	}

	/*Status Network::send(SOCKET sock, const char* buffer, int size, int flags) {

		if (::send(sock, buffer, size, flags) == SOCKET_ERROR) {
			return Status::Error;
		}

		return Status::Success;
	}*/

	/*Status Network::recieve(SOCKET sock, char* buffer, int size, int flags) {

	}*/

	Status Network::shutdown(SOCKET sock) {

		if (::shutdown(sock, SD_SEND) == SOCKET_ERROR) {
			return Status::Error;
		}

		return Status::Success;
	}

	Status Network::close(SOCKET sock) {

		if (::closesocket(sock) == SOCKET_ERROR) {
			return Status::Error;
		}

		return Status::Success;
	}

}