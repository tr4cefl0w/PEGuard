#include "TCPClient.h"

namespace Client
{
	Status TCPClient::init()
	{
		if (WSAStartup(MAKEWORD(2, 2), &m_wsaData) != NULL)
			return Status::Error;

		return Status::Success;
	}

	Status TCPClient::establish()
	{
		m_info.ai_family = AF_INET;
		m_info.ai_socktype = SOCK_STREAM;
		m_info.ai_protocol = IPPROTO_TCP;

		getaddrinfo(m_ipv4, m_port, &m_info, &m_result);

		m_connection = socket(m_result->ai_family, m_result->ai_socktype, m_result->ai_protocol);

		if (connect(m_connection, m_result->ai_addr, (int)m_result->ai_addrlen) != NULL)
			return Status::Error;

		return Status::Success;
	}

	std::int32_t TCPClient::get_error()
	{
		return WSAGetLastError();
	}

}
