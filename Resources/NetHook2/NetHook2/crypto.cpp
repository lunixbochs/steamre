

#include "crypto.h"

#include "logger.h"
#include "csimplescan.h"


bool (__cdecl *Encrypt_Orig)(const uint8*, uint32, uint8*, uint32*, uint32) = 0;
bool (__cdecl *Decrypt_Orig)(const uint8*, uint32, uint8*, uint32*, const uint8*, uint32) = 0;
bool (__cdecl *GetMessageFn)( int * ) = 0;

CCrypto::CCrypto()
{
	CSimpleScan steamClientScan( "steamclient.dll" );

	bool bRet = steamClientScan.FindFunction( 
		"\x55\x8B\xEC\x6A\xFF\x68\x01\x47\x32\x38\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x81\xEC\x04\x09\x00\x00",
		"xxxxxx????xxxxxxxxxxxxxxxxxxxx",
		(void **)&Encrypt_Orig
	);

	g_pLogger->LogConsole( "CCrypto::SymmetricEncrypt = 0x%x \n", Encrypt_Orig );


	bRet = steamClientScan.FindFunction(
		"\x55\x8B\xEC\x6A\xFF\x68\x21\x74\x28\x38\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x81\xEC\xE8\x04\x00\x00",
		"xxxxxx????xxxxxxxxxxxxxxxxxxx",
		(void **)&Decrypt_Orig
	);

	g_pLogger->LogConsole( "CCrypto::SymmetricDecrypt = 0x%x\n", Decrypt_Orig );

	bRet = steamClientScan.FindFunction(
		"\x51\xA1\x00\x95\x32\x38\x8B\x08\x85\xC9\x75\x05\x89\x0C\x24\xEB\x28\xE8",
		"xx????xxxxxxxxxxxx",
		(void **)&GetMessageFn
	);

	g_pLogger->LogConsole( "CMessageList::GetMessage = 0x%x\n", GetMessageFn );

	for ( int x = 0; x < 8000; ++x )
	{
		const char *szMsg = this->GetMessage( (EMsg)x );

		if ( szMsg == NULL )
			continue;

		g_pLogger->LogFile( "emsg_list.txt", false, "\t%s = %d,\r\n", szMsg, x );
	}

	static bool (__cdecl *encrypt)(const uint8*, uint32, uint8*, uint32*, uint32) = &CCrypto::SymmetricEncrypt;
	static bool (__cdecl *decrypt)(const uint8*, uint32, uint8*, uint32*, const uint8*, uint32) = &CCrypto::SymmetricDecrypt;

	Encrypt_Detour = new CSimpleDetour((void **) &Encrypt_Orig, *(void**) &encrypt);
	Decrypt_Detour = new CSimpleDetour((void **) &Decrypt_Orig, *(void**) &decrypt);

	Encrypt_Detour->Attach();
	Decrypt_Detour->Attach();
}

CCrypto::~CCrypto()
{
	Encrypt_Detour->Detach();
	Decrypt_Detour->Detach();

	delete Encrypt_Detour;
	delete Decrypt_Detour;
}



// This call got strangely optimized. Don't clobber ECX.
__declspec(naked) bool __cdecl CCrypto::SymmetricEncrypt( const uint8 *pubPlaintextData, uint32 cubPlaintextData, uint8 *pubEncryptedData, uint32 *pcubEncryptedData, uint32 cubKey )
{
	__asm {
		// prologue
		push ebp;
		mov ebp, esp;
		sub esp, __LOCAL_SIZE;

		// this needs to be saved (aes key)
		push ecx;
	}

	g_pLogger->LogNetMessage( k_eNetOutgoing, (uint8 *)pubPlaintextData, cubPlaintextData );

	__asm {
		// call it manually here, prevent
		// it from 'helpfully' using ECX

		// prep aes key in register
		pop ecx;

		// push args
		push cubKey;
		push pcubEncryptedData;
		push pubEncryptedData;
		push cubPlaintextData;
		push pubPlaintextData;

		// call!
		call Encrypt_Orig;

		// cleanup
		add esp, 0x14;

		// epilogue
		mov esp, ebp;
		pop ebp;
		ret;
	}
}

// This function is considerably less retarded
bool __cdecl CCrypto::SymmetricDecrypt( const uint8 *pubEncryptedData, uint32 cubEncryptedData, uint8 *pubPlaintextData, uint32 *pcubPlaintextData, const uint8 *pubKey, uint32 cubKey )
{
	bool ret = (*Decrypt_Orig)(pubEncryptedData, cubEncryptedData, pubPlaintextData, pcubPlaintextData, pubKey, cubKey);

	g_pLogger->LogNetMessage( k_eNetIncoming, pubPlaintextData, *pcubPlaintextData );

	return ret;
}


const char* CCrypto::GetMessage( EMsg eMsg )
{
	static char *szMsg = new char[ 200 ];

	int ieMsg = (int)eMsg;

	bool bRet = false;

	__asm
	{
		pushad

		lea esi, [ szMsg ]
		mov ecx, 200
		mov edi, ieMsg

		push 0xFF

		call GetMessageFn
		mov bRet, al

		popad
	}

	if ( bRet )
		return szMsg;

	return NULL;
}