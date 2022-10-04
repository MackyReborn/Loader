#include <Windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <WinINet.h>
#include <filesystem>
#include <thread>

#include <TlHelp32.h>

#pragma comment(lib, "WinINet.lib")
#pragma comment(lib, "urlmon.lib")
#include <urlmon.h>

#include "cWinsock.h"
#include "AES.h"
#include "json.hpp"
#include "XOR.h"

#include "SHA512.h"

using std::string;
using json = nlohmann::json;

cWinSock* wSock = new cWinSock;

bool shouldBan = false;
std::string uAgentFromServer;

std::string uName, pWord;

bool isUpdated()
{
	int curVersion = 14;

	IStream* stream;

	string usernameString = ("https://voidrealm.xyz/forum/version.php?version=" + std::to_string(curVersion));
	//usernameString.append(std::to_string(curVersion));

	HRESULT result = URLOpenBlockingStream(0, (usernameString).c_str(), &stream, 0, 0);

	if (result != 0) return false;

	char buffer[100];
	unsigned long bytesRead;
	std::stringstream ss;

	stream->Read(buffer, sizeof(buffer), &bytesRead);

	while (bytesRead > 0U)
	{
		ss.write(buffer, (long long)bytesRead);
		stream->Read(buffer, sizeof(buffer), &bytesRead);
	}
	stream->Release();
	string resultString = ss.str();

	if (resultString.find("0") != -1)
	{
		return true;
	}
	else if (resultString.find("1") != -1)
	{
		return false;
	}
}

int getUniqueIdentifier()
{
	SYSTEM_INFO siSysInfo;
	GetSystemInfo(&siSysInfo);
	int resultantHWID = siSysInfo.dwNumberOfProcessors + siSysInfo.wProcessorArchitecture + siSysInfo.dwProcessorType;

	return resultantHWID;
}

bool authenticate(string& username, string& password)
{
	IStream* stream;

	string usernameString = "https://voidrealm.xyz/forum/check.php?username=" + username + "&password=" + password + "&key=DLDtb9ZpM97dyglOzsLe";
	//usernameString.append(username);
	//usernameString.append("&password=");
	//usernameString.append(password);
	HRESULT result = URLOpenBlockingStream(0, (usernameString).c_str(), &stream, 0, 0);
	
	if (result != 0) return false;

	char buffer[100];
	unsigned long bytesRead;
	std::stringstream ss;

	stream->Read(buffer, sizeof(buffer), &bytesRead);

	while (bytesRead > 0U)
	{
		ss.write(buffer, (long long)bytesRead);
		stream->Read(buffer, sizeof(buffer), &bytesRead);
	}
	stream->Release();
	string resultString = ss.str();

	if (resultString.find("0") != -1)
	{
		return false;
	}
	else if (resultString.find("2") != -1)
	{
		return false;
	}
	else if (resultString.find("C4tPy") != -1)
	{
		uAgentFromServer = resultString;
		return true;
	}

	return false;
}

bool banUser(string& username, string& password)
{
	IStream* stream;

	string usernameString = "https://voidrealm.xyz/forum/ban.php?username=" + username + "&password=" + password;
	//usernameString.append(username);
	//usernameString.append("&password=");
	//usernameString.append(password);
	HRESULT result = URLOpenBlockingStream(0, (usernameString).c_str(), &stream, 0, 0);

	if (result != 0) return false;

	char buffer[100];
	unsigned long bytesRead;
	std::stringstream ss;

	stream->Read(buffer, sizeof(buffer), &bytesRead);

	while (bytesRead > 0U)
	{
		ss.write(buffer, (long long)bytesRead);
		stream->Read(buffer, sizeof(buffer), &bytesRead);
	}
	stream->Release();
	string resultString = ss.str();

	if (resultString.find("0") != -1)
	{
		return false;
	}
	else if (resultString.find("1") != -1)
	{
		return true;
	}
	else if (resultString.find("2") != -1)
	{
		return false;
	}

	return false;
}

bool checkHWID(string& username)
{
	SYSTEM_INFO siSysInfo;
	GetSystemInfo(&siSysInfo);
	int resultantHWID = siSysInfo.dwNumberOfProcessors + siSysInfo.wProcessorArchitecture + siSysInfo.dwProcessorType;
	
	IStream* stream;

	std::string processorIDStr = std::to_string(resultantHWID);
	std::string preHWID = processorIDStr + username;
	std::string postHWID = sha512(preHWID);

	string usernameString = "https://voidrealm.xyz/forum/hwid.php?username=" + username + "&hwid=" + postHWID + "&key=scVska9QrHl6pjt4jEBD";
	//usernameString.append(username);
	//usernameString.append("&hwid=");
	//usernameString.append(std::to_string(resultantHWID));
	HRESULT result = URLOpenBlockingStream(0, (usernameString).c_str(), &stream, 0, 0);

	if (result != 0) return false;

	char buffer[100];
	unsigned long bytesRead;
	std::stringstream ss;

	stream->Read(buffer, sizeof(buffer), &bytesRead);

	while (bytesRead > 0U)
	{
		ss.write(buffer, (long long)bytesRead);
		stream->Read(buffer, sizeof(buffer), &bytesRead);
	}
	stream->Release();
	string resultString = ss.str();

	if (resultString.find("0") != -1)
	{
		MessageBoxA(NULL, "HWID Mismatch. Please Request a Reset on the Forums", "Error", MB_OK);
		delete wSock;
		ExitProcess(EXIT_FAILURE);
	}
	else if (resultString.find("2") != -1)
	{
		MessageBoxA(NULL, "HWID Could not Be Resolved", "Error", MB_OK);
		delete wSock;
		ExitProcess(EXIT_FAILURE);
	}
	else if (resultString.find("3") != -1)
	{
		std::cout << "HWID Registered" << std::endl;
	}
	else if (resultString.find("1") != -1)
	{
		return true;
	}

	return false;
}

int getUserGroup(string& username)
{
	IStream* stream;

	string usernameString = "https://voidrealm.xyz/forum/group.php?username=" + username;
	//usernameString.append(username);
	HRESULT result = URLOpenBlockingStream(0, (usernameString).c_str(), &stream, 0, 0);

	if (result != 0) return false;

	char buffer[100];
	unsigned long bytesRead;
	std::stringstream ss;

	stream->Read(buffer, sizeof(buffer), &bytesRead);

	while (bytesRead > 0U)
	{
		ss.write(buffer, (long long)bytesRead);
		stream->Read(buffer, sizeof(buffer), &bytesRead);
	}
	stream->Release();
	string resultString = ss.str();

	return std::stoi(resultString);
	/*
	if (resultString.find("4") != -1)
	{
		return 4; // Administrator
	}
	else if (resultString.find("8") != -1)
	{
		return 8; // VIP
	}
	else if (resultString.find("10") != -1)
	{
		return 10; // Beta
	}
	else if (resultString.find("3") != -1)
	{
		return 3; // Super Moderator
	}
	else if (resultString.find("7") != -1)
	{
		return 7; // Banned
	}
	else if (resultString.find("6") != -1)
	{
		return 6; // Moderator
	}
	else if (resultString.find("14") != -1)
	{
		return 14; // Skinchanger
	}
	else if (resultString.find("12") != -1)
	{
		return 12; // MP
	}
	else if (resultString.find("11") != -1)
	{
		return 11; // TF2
	}
	else
	{
		return NULL;
	}
	*/
}

const char* getUserGroupText(int userGroup)
{
	switch (userGroup)
	{
	case 4:
		return "Administrator";
		break;
	case 8:
		return "CSGO";
		break;
	case 10:
		return "Beta";
		break;
	case 3:
		return "Super Moderator";
		break;
	case 6:
		return "Moderator";
		break;
	case 7:
		return "Banned";
		break;
	case 11:
		return "TF2";
		break;
	case 12:
		return "Master Package";
		break;
	case 14:
		return "Skinchanger";
		break;
	case 15:
		return "Rust";
	default:
		return "Unauth";
		break;
	}
}

std::vector<unsigned char, std::allocator<unsigned char>> saveUsername(string user)
{
	std::vector<unsigned char> key = plusaes::key_from_string(&"OdTw1MLU6JGiBT2f"); // 16-char = 128-bit

	const unsigned char iv[16] =
	{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};

	unsigned long encrypted_size = plusaes::get_padded_encrypted_size(user.size());
	std::vector<unsigned char> encrypted(encrypted_size);
	plusaes::encrypt_cbc((unsigned char*)user.data(), user.size(), &key[0], key.size(), &iv, &encrypted[0], encrypted.size(), true);

	return encrypted;
}

std::vector<unsigned char, std::allocator<unsigned char>> savePassword(string pass)
{
	std::vector<unsigned char> key = plusaes::key_from_string(&"OdTw1MLU6JGiBT2f"); // 16-char = 128-bit

	const unsigned char iv[16] =
	{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};

	unsigned long encrypted_size = plusaes::get_padded_encrypted_size(pass.size());
	std::vector<unsigned char> encrypted(encrypted_size);
	plusaes::encrypt_cbc((unsigned char*)pass.data(), pass.size(), &key[0], key.size(), &iv, &encrypted[0], encrypted.size(), true);

	return encrypted;
}

bool saveClient(string user, string pass)
{
	auto encryptedUser = saveUsername(user);
	auto encryptedPass = savePassword(pass);
	unsigned long userSize = plusaes::get_padded_encrypted_size(user.size());
	unsigned long passSize = plusaes::get_padded_encrypted_size(pass.size());

	json j;
	std::ofstream o("c.json");
	if (!o.is_open()) return false;

	j["s"] = userSize;
	j["u"] = encryptedUser;
	j["p"] = encryptedPass;
	j["ps"] = passSize;

	o << std::setw(4) << j << std::endl;

	o.close();

	return true;
}

unsigned char* getUsername()
{
	json j;
	std::ifstream i("c.json");
	if (!i.is_open()) return NULL;
	i >> j;

	std::vector<unsigned char> key = plusaes::key_from_string(&"OdTw1MLU6JGiBT2f"); // 16-char = 128-bit
	const unsigned char iv[16] =
	{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	unsigned long encrypted_size;
	encrypted_size = j["s"];

	std::vector<unsigned char> encrypted = j["u"];

	unsigned long padded_size = 0;
	std::vector<unsigned char> decrypted(encrypted_size);
	plusaes::decrypt_cbc(&encrypted[0], encrypted.size(), &key[0], key.size(), &iv, &decrypted[0], decrypted.size(), &padded_size);

	i.close();

	return decrypted.data();
}

unsigned char* getPassword()
{
	json j;
	std::ifstream i("c.json");
	if (!i.is_open()) return NULL;
	i >> j;

	std::vector<unsigned char> key = plusaes::key_from_string(&"OdTw1MLU6JGiBT2f"); // 16-char = 128-bit
	const unsigned char iv[16] =
	{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	unsigned long encrypted_size;
	encrypted_size = j["ps"];

	std::vector<unsigned char> encrypted = j["p"];

	unsigned long padded_size = 0;
	std::vector<unsigned char> decrypted(encrypted_size);
	plusaes::decrypt_cbc(&encrypted[0], encrypted.size(), &key[0], key.size(), &iv, &decrypted[0], decrypted.size(), &padded_size);

	i.close();

	return decrypted.data();
}

bool findProc(const char* procName)
{
	HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(procEntry);

	do
		if (!strcmp(procEntry.szExeFile, procName))
		{
			CloseHandle(hPID);
			return true;
		}
	while (Process32Next(hPID, &procEntry));
	CloseHandle(hPID);
	return false;
}

time_t start = NULL;
bool timePassed(int seconds)
{
	double seconds_since_start = (time(0) - start);

	if (seconds_since_start > seconds)
	{
		return true;
	}
}

void antiDebug()
{
	while (true)
	{
		BOOL debuggerFound = IsDebuggerPresent();

		if (debuggerFound)
			shouldBan = true;

		/*
		if (timePassed(45))
		{
			MessageBoxA(NULL, "Loader Timeout", "Error", MB_OK);
			delete wSock;
			ExitProcess(EXIT_FAILURE);
		}
		*/

		if (findProc("Fiddler.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1800", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("de4dot.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1801", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("PEiD.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1802", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("MegaDumper.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1803", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("Universal_Fixer.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1804", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("Wireshark.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1805", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("OLLYDBG.EXE"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1806", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("ida.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1807", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("GlassWire.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1808", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("x64dbg.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1809", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("x32dbg.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1810", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("x96dbg.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1811", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("cheatengine-x86_64.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1812", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		if (findProc("ProcessHacker.exe"))
		{
			//delete wSock;
			//MessageBoxA(NULL, "Error Code 1813", "Error", MB_OK);
			shouldBan = true;
			//ExitProcess(EXIT_FAILURE);
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
}

void checkBan()
{
	while (true)
	{
		if (shouldBan)
		{
			if (banUser(uName, pWord))
			{
				MessageBoxA(NULL, "EULA Breach", "Error", MB_OK);
				delete wSock;
				ExitProcess(EXIT_FAILURE);
			}
			MessageBoxA(NULL, "EULA Breach", "Error", MB_OK);
			delete wSock;
			ExitProcess(EXIT_FAILURE);
		}
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

int main(int argc, char* argv[])
{
	start = time(0);
	SetConsoleTitleA(TEXT(""));
	
	if (!isUpdated())
	{
		MessageBoxA(NULL, "Your Client is Outdated. Please Redownload from the Forums.", "Outdated Client", MB_OK);
		delete wSock;
		ExitProcess(EXIT_FAILURE);
	}
	
	bool closeSteam = true;

	if (argc > 1)
	{
		if (!strcmp(argv[1], "-insecure"))
		{
			SetConsoleTitleA(TEXT("Void Realm Loader (Insecure)"));
			closeSteam = false;
		}
	}
	
	if (findProc("steam.exe") && closeSteam)
	{
		MessageBoxA(NULL, "Never Open the Loader with Steam!\nSteam Has Been Killed!", "Steam Open!", MB_OK);
		system("taskkill /F /T /IM Steam.exe");
		system("cls");
		//MessageBoxA(NULL, "Never Open the Loader with Steam!", "ERROR", MB_OK);
		//delete wSock;
		//ExitProcess(EXIT_FAILURE);
	}
	
	std::thread antiDebugThread(antiDebug);

	std::filesystem::file_status s = std::filesystem::file_status{};
	string username;
	string password;

	if (std::filesystem::status_known(s) ? std::filesystem::exists(s) : std::filesystem::exists("c.json"))
	{
		username = reinterpret_cast<char*>(getUsername());
		password = reinterpret_cast<char*>(getPassword());
	}
	else
	{
		std::cout << "Login" << std::endl;
		std::cout << "Enter Username: ";
		std::cin >> username;
		std::cout << "Enter Password: ";
		std::cin >> password;
	}
	system("cls");

	std::string hashedPassword = sha512(password);

	uName = username;
	pWord = hashedPassword;

	std::thread banThread(checkBan);

	if (authenticate(username, hashedPassword))
	{
		saveClient(username, password);
	}
	else
	{
		MessageBoxA(NULL, "Invalid Credentials", "Error", MB_OK);
		delete wSock;
		ExitProcess(EXIT_FAILURE);
	}

	checkHWID(username);

	int uGroup = getUserGroup(username);

	const char* uGroupstr = getUserGroupText(uGroup);

	if (!strcmp("Unauth", uGroupstr))
	{
		MessageBoxA(NULL, "Your Subscription has Expired!", "Error", MB_OK);
		delete wSock;
		ExitProcess(EXIT_FAILURE);
	}
	if (!strcmp("Banned", uGroupstr))
	{
		MessageBoxA(NULL, "You Have Been Banned. Please Contact an Administrator.", "Error", MB_OK);
		delete wSock;
		ExitProcess(EXIT_FAILURE);
	}

	std::cout << "Subscription Tier: " << uGroupstr << std::endl;
	std::cout << "\n";

	if (uGroup == 4 || uGroup == 10 || uGroup == 3 || uGroup == 6) // Admins and Beta
	{
		int cSelection;
		std::cout << "CS:GO External Framework\n1.VIP\n2.Beta\n3.Skinchanger Only\n" << std::endl;
		
		if (uGroup == 4 || uGroup == 3)
		{
			std::cout << "CS:GO Internal Framework\n4.Alpha\n" << std::endl;
		}

		std::cout << "TF2 External Framework\n5.VIP\n"<< std::endl;
		std::cout << "Rust External Framework\n6.VIP\n" << std::endl;

		std::cin >> cSelection;

		if (uGroup == 10 || uGroup == 6)
		{
			if (cSelection == 4)
				cSelection += 1;
		}

		wSock->downloadBinary(cSelection);
	}
	else if (uGroup == 12) // Master Package
	{
		int cSelection;
		std::cout << "CS:GO External Framework\n1.VIP\n2.Skinchanger Only\n" << std::endl;
		std::cout << "TF2 External Framework\n3.VIP\n" << std::endl;
		std::cout << "Rust External Framework\n4.VIP\n" << std::endl;

		std::cin >> cSelection;

		if (cSelection == 2)
		{
			cSelection += 1;
		}

		if (cSelection == 3)
		{
			cSelection += 2;
		}

		if (cSelection == 4)
		{

		}
		else
		{
			wSock->downloadBinary(cSelection);
		}
	}
	else if (uGroup == 8) // CSGO VIP
	{
		wSock->downloadBinary(1);
	}
	else if (uGroup == 11) // TF2 VIP
	{
		wSock->downloadBinary(5);
	}
	else if (uGroup == 14) // Skinchanger
	{
		wSock->downloadBinary(3);
	}
	else if (uGroup == 15)
	{
		wSock->downloadBinary(6);
	}

	delete wSock;
	//ExitProcess(EXIT_SUCCESS);
}