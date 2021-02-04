// LongRmDir.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define _WIN32_WINNT 0x0501
#include <iostream>
#include <Windows.h>
#include <accctrl.h>
#include <aclapi.h>
#pragma comment (lib,"Advapi32.lib")
#define IsDirectory(a)                  ((a) & FILE_ATTRIBUTE_DIRECTORY)
#define IsReparse(a)                    ((a) & FILE_ATTRIBUTE_REPARSE_POINT)

#define LONG_MAX_PATH 32768

BOOL bRebootRequired = FALSE;

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		std::wcerr << L"LookupPrivilegeValue error: " << GetLastError() << std::endl;
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		std::wcerr << L"AdjustTokenPrivileges error: " << GetLastError() << std::endl;
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		std::wcerr << L"The token does not have the specified privilege." << std::endl;
		return FALSE;
	}

	return TRUE;
}

BOOL TakeOwnership(const WCHAR* lpszOwnFile)
{
	BOOL bRetval = FALSE;

	HANDLE hToken = NULL;
	PSID pSIDAdmin = NULL;
	PSID pSIDEveryone = NULL;
	PACL pACL = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	const int NUM_ACES = 2;
	EXPLICIT_ACCESS ea[NUM_ACES];
	DWORD dwResult;

	// Specify the DACL to use.
	// Create a SID for the Everyone group.
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
		SECURITY_WORLD_RID,
		0,
		0, 0, 0, 0, 0, 0,
		&pSIDEveryone))
	{
		std::wcerr << L"AllocateAndInitializeSid (Everyone) error " << GetLastError() << std::endl;
		goto Cleanup;
	}

	// Create a SID for the BUILTIN\Administrators group.
	if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pSIDAdmin))
	{
		std::wcerr << L"AllocateAndInitializeSid (Admin) error " << GetLastError() << std::endl;
		goto Cleanup;
	}

	ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

	// Set read access for Everyone.
	ea[0].grfAccessPermissions = GENERIC_READ;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pSIDEveryone;

	// Set full control for Administrators.
	ea[1].grfAccessPermissions = GENERIC_ALL;
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[1].Trustee.ptstrName = (LPTSTR)pSIDAdmin;

	dwResult = SetEntriesInAcl(NUM_ACES,
		ea,
		NULL,
		&pACL);

	if (dwResult != ERROR_SUCCESS)
	{
		std::wcerr << L"Failed SetEntriesInAcl Error: " << dwResult << std::endl;
		goto Cleanup;
	}

	// Try to modify the object's DACL.
	dwResult = SetNamedSecurityInfoW(
		(LPWSTR)lpszOwnFile,                 // name of the object
		SE_FILE_OBJECT,              // type of object
		DACL_SECURITY_INFORMATION,   // change only the object's DACL
		NULL, NULL,                  // do not change owner or group
		pACL,                        // DACL specified
		NULL);                       // do not change SACL

	if (dwResult == ERROR_SUCCESS)
	{
		std::wcout << L"Successfully changed DACL" << std::endl;
		bRetval = TRUE;
		// No more processing needed.
		goto Cleanup;
	}
	if (dwResult != ERROR_ACCESS_DENIED)
	{
		std::wcerr << L"First SetNamedSecurityInfo call failed: " << dwResult << std::endl;
		goto Cleanup;
	}

	// If the preceding call failed because access was denied, 
	// enable the SE_TAKE_OWNERSHIP_NAME privilege, create a SID for 
	// the Administrators group, take ownership of the object, and 
	// disable the privilege. Then try again to set the object's DACL.

	// Open a handle to the access token for the calling process.
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES,
		&hToken))
	{
		std::wcerr << L"OpenProcessToken failed: " << GetLastError() << std::endl;
		goto Cleanup;
	}

	// Enable the SE_TAKE_OWNERSHIP_NAME privilege.
	if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE))
	{
		std::wcerr << L"You must be logged on as Administrator." << std::endl;
		goto Cleanup;
	}

	// Set the owner in the object's security descriptor.
	dwResult = SetNamedSecurityInfo(
		(LPWSTR)lpszOwnFile,                 // name of the object
		SE_FILE_OBJECT,              // type of object
		OWNER_SECURITY_INFORMATION,  // change only the object's owner
		pSIDAdmin,                   // SID of Administrator group
		NULL,
		NULL,
		NULL);

	if (dwResult != ERROR_SUCCESS)
	{
		std::wcerr << L"Could not set owner. Error: " << dwResult << std::endl;
		goto Cleanup;
	}

	// Disable the SE_TAKE_OWNERSHIP_NAME privilege.
	if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, FALSE))
	{
		dwResult = GetLastError();
		std::wcerr << L"Failed SetPrivilege call unexpectedly. Error: " << dwResult << std::endl;
		goto Cleanup;
	}

	// Try again to modify the object's DACL,
	// now that we are the owner.
	dwResult = SetNamedSecurityInfo(
		(LPWSTR)lpszOwnFile,                 // name of the object
		SE_FILE_OBJECT,              // type of object
		DACL_SECURITY_INFORMATION,   // change only the object's DACL
		NULL, NULL,                  // do not change owner or group
		pACL,                        // DACL specified
		NULL);                       // do not change SACL

	if (dwResult == ERROR_SUCCESS)
	{
		std::wcout << L"Successfully updated DACL" << std::endl;
		bRetval = TRUE;
	}
	else
	{
		std::wcerr << L"Second SetNamedSecurityInfo call failed. Error: " << dwResult << std::endl;
	}

Cleanup:

	if (pSIDAdmin)
		FreeSid(pSIDAdmin);

	if (pSIDEveryone)
		FreeSid(pSIDEveryone);

	if (pACL)
		LocalFree(pACL);

	if (hToken)
		CloseHandle(hToken);

	return bRetval;

}

LSTATUS
RemoveDirectoryForce(
	const WCHAR* pszDirectory
)
{
	LSTATUS		Status = ERROR_SUCCESS;
	DWORD		Attr;
	WCHAR		szRootPath[4];
	WCHAR* pFilePart;

	if (GetFullPathName(pszDirectory, 4, szRootPath, &pFilePart) == 3 &&
		szRootPath[1] == ':' &&
		szRootPath[2] == '\\'
		) {
		// don't delete root directory
		return ERROR_SUCCESS;
	}

	if (!RemoveDirectoryW(pszDirectory)) 
	{
		Status = (LSTATUS)GetLastError();
		switch (Status)
		{
			case ERROR_SHARING_VIOLATION:
				std::wcout << L"Directory '" << pszDirectory << "' is in use. Will remove on reboot." << std::endl;
				if (!MoveFileExW(pszDirectory, NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
				{
					std::wcerr << L"Unable to remove on reboot Error: " << GetLastError() << std::endl;
				}
				else
				{
					bRebootRequired = true;
					Status = ERROR_SUCCESS;
				}
				break;
			case ERROR_ACCESS_DENIED:
				std::wcout << L"Taking ownership of '" << pszDirectory << L"'" << std::endl;
				TakeOwnership(pszDirectory);
				Attr = GetFileAttributesW(pszDirectory);

				if (Attr != 0xFFFFFFFF)
				{
					if (Attr & FILE_ATTRIBUTE_READONLY)
					{
						std::wcout << L"Clearing READ ONLY attribute on '" << pszDirectory << L"'" << std::endl;
						Attr &= ~FILE_ATTRIBUTE_READONLY;
					}

					if (Attr & FILE_ATTRIBUTE_SYSTEM)
					{
						std::wcout << L"Clearing SYSTEM attribute on '" << pszDirectory << L"'" << std::endl;
						Attr &= ~FILE_ATTRIBUTE_SYSTEM;
					}

					if (SetFileAttributesW(pszDirectory, Attr)) {

						if (RemoveDirectoryW(pszDirectory)) {
							Status = ERROR_SUCCESS;
						}
						else {
							Status = GetLastError();
							std::wcerr << "FAILED TO CHANGE FILE ATTRIBUTES ERR#" << Status << std::endl;

						}
					}
				}
				break;
		}
	}

	return Status;
}

LSTATUS RemoveDirectoryAndSubdirectories(
	std::wstring pszDirectory,
	OUT BOOL* AllEntriesDeleted
)

{
	HANDLE          find_handle;
	DWORD           attr;
	DWORD			s;
	BOOL            all_deleted;
	int             dir_len, new_len;
	std::wstring    new_str;
	WIN32_FIND_DATA find_data;
	std::wstring    pszFileBuffer;
	DWORD			dwResult;
	BOOL			bResult;
	*AllEntriesDeleted = TRUE;

	dir_len = pszDirectory.length();

	if (dir_len == 0) {
		return ERROR_BAD_PATHNAME;
	}

	if (dir_len + 3 > LONG_MAX_PATH) {
		return RemoveDirectoryForce(pszDirectory.c_str());
	}

	pszFileBuffer = std::wstring(pszDirectory);

	if (dir_len && pszDirectory[dir_len - 1] != ':' &&
		pszDirectory[dir_len - 1] != '\\') {
		pszFileBuffer += L"\\";
		dir_len++;
	}
	 
	pszFileBuffer += L"*";

	find_handle = FindFirstFile(pszFileBuffer.c_str(), &find_data);
	if (find_handle == INVALID_HANDLE_VALUE) {
		return RemoveDirectoryForce(pszDirectory.c_str());
	}

	do {
		new_str = std::wstring(find_data.cFileName);
		new_len = new_str.length();

		if (dir_len + new_len >= LONG_MAX_PATH) {
			*AllEntriesDeleted = FALSE;
			std::wcerr << L"ERROR: PATH TOO LONG '" << new_str.c_str() << L"'" << std::endl;
			break;
		}
		
		pszFileBuffer = pszFileBuffer.substr(0,dir_len) + new_str;

		// display filename being processed
		if (pszFileBuffer.find(L"\\\\?\\UNC\\") == 0)
		{
			std::wcout << pszFileBuffer.c_str() + 8 << std::endl;
		}
		else if (pszFileBuffer.find(L"\\\\?\\", 4) == 0)
		{
			std::wcout << pszFileBuffer.c_str() << std::endl;
		}
		else
		{
			std::wcout << pszFileBuffer.c_str() << std::endl;
		}
		attr = find_data.dwFileAttributes;

		if (!wcscmp(find_data.cFileName, L".") ||
			!wcscmp(find_data.cFileName, L"..")) {
			continue;
		}

		DWORD attr = GetFileAttributesW(pszFileBuffer.c_str());
		if (attr == 0xFFFFFFFF)
		{
			dwResult = GetLastError();
			std::wcerr << L"Unale to get file attributes for '" << pszFileBuffer.c_str() << L"' Err#" << dwResult << std::endl;
		}
		if (IsDirectory(attr) && !IsReparse(attr)) {

			s = RemoveDirectoryAndSubdirectories(pszFileBuffer, &all_deleted);

			if (s != ERROR_SUCCESS) {
				*AllEntriesDeleted = FALSE;
				if (s != ERROR_DIR_NOT_EMPTY || all_deleted) {
					std::wcerr << L"ERROR: FAILED TO DELETE '" << pszFileBuffer.c_str() << L"' Err#" << s << std::endl;
				}
			}
		}
		else {

			if (attr & FILE_ATTRIBUTE_READONLY) {
				SetFileAttributes(pszFileBuffer.c_str(), attr & (~FILE_ATTRIBUTE_READONLY));
			}

			if (attr & FILE_ATTRIBUTE_SYSTEM) {
				SetFileAttributes(pszFileBuffer.c_str(), attr & (~FILE_ATTRIBUTE_SYSTEM));
			}

			if (!(IsDirectory(attr)))
			{
				bResult = DeleteFileW(pszFileBuffer.c_str());
				if (!bResult)
				{
					dwResult = GetLastError();
					switch (dwResult)
					{
						case ERROR_ACCESS_DENIED:
							std::wcout << L"Taking ownership of '" << pszFileBuffer.c_str() << "'" << std::endl;
							// take ownership of file and grant access
							TakeOwnership(pszFileBuffer.c_str());
							attr = GetFileAttributesW(pszFileBuffer.c_str());
							if (attr != 0xFFFFFFFF)
							{
								if (attr & FILE_ATTRIBUTE_READONLY) {
									SetFileAttributes(pszFileBuffer.c_str(), attr & (~FILE_ATTRIBUTE_READONLY));
								}

								if (attr & FILE_ATTRIBUTE_SYSTEM) {
									SetFileAttributes(pszFileBuffer.c_str(), attr & (~FILE_ATTRIBUTE_SYSTEM));
								}
							}
							bResult = DeleteFileW(pszFileBuffer.c_str());
							if (bResult != ERROR_SUCCESS)
							{
								std::wcout << L"Unable to delete file '" << pszFileBuffer.c_str() << "'. Will attempt to remove on reboot." << std::endl;
								if (!MoveFileExW(pszFileBuffer.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
								{
									std::wcerr << L"Unable to remove on reboot Error: " << GetLastError() << std::endl;
								}
								else
								{
									bRebootRequired = true;
									bResult = ERROR_SUCCESS;
								}
							}
							break;
						case ERROR_SHARING_VIOLATION:
							std::wcout << L"File '" << pszFileBuffer.c_str() << "' is in use. Will remove on reboot." << std::endl;
							if (!MoveFileExW(pszFileBuffer.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
							{
								std::wcerr << L"Unable to remove on reboot Error: " << GetLastError() << std::endl;
							}
							else
							{
								bRebootRequired = true;
								bResult = ERROR_SUCCESS;
							}
							break;
					}

					if (bResult != ERROR_SUCCESS)
					{
						std::wcerr << L"ERROR: FAILED TO DELETE '" << pszFileBuffer.c_str() << L"' Err#" << dwResult << std::endl;
					}
				}
			}

			if ((IsDirectory(attr) && IsReparse(attr) && RemoveDirectoryForce(pszFileBuffer.c_str()) != ERROR_SUCCESS))
			{

				s = GetLastError();
				if (s == ERROR_REQUEST_ABORTED)
					break;

				dwResult = GetLastError();
				std::wcerr << L"ERROR: FAILED TO DELETE '" << pszFileBuffer.c_str() << L"' Err#" << dwResult << std::endl;
				SetFileAttributesW(pszFileBuffer.c_str(), attr);
				*AllEntriesDeleted = FALSE;
			}
		}
	} while (FindNextFile(find_handle, &find_data));

	FindClose(find_handle);
	return RemoveDirectoryForce(pszDirectory.c_str());
}


int wmain(int argc, wchar_t* argv[])
{
	// disable wow64 redirection if API is present
	// not imported to prevent breaking on 32-bit OS 
	typedef BOOL WINAPI fntype_Wow64DisableWow64FsRedirection(PVOID * OldValue);
	auto pfnWow64DisableWow64FsRedirection = (fntype_Wow64DisableWow64FsRedirection*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Wow64DisableWow64FsRedirection");

	if (pfnWow64DisableWow64FsRedirection) {
		// function found, call it via pointer
		PVOID arg;
		(*pfnWow64DisableWow64FsRedirection)(&arg);
	}
	else {
		// function was missing ... don't care
	}

	if (argc == 2)
	{
		WCHAR* initialPath = argv[1];
		std::wcout << L"Removing dirctory : '" << initialPath << L"'" << std::endl;
		WCHAR targetPath[LONG_MAX_PATH];
		BOOL allDeleted = false;

		if (initialPath[0] == '\\' &&
			initialPath[1] == '\\' &&
			initialPath[2] != '?')
		{
			wcscpy_s(targetPath, LONG_MAX_PATH, L"\\\\?\\UNC\\");
			wcscat_s(targetPath, LONG_MAX_PATH - 8, initialPath+2);
		}
		if (initialPath[1] == ':')
		{
			wcscpy_s(targetPath, LONG_MAX_PATH, L"\\\\?\\");
			wcscat_s(targetPath, LONG_MAX_PATH - 4, initialPath);
		}
		RemoveDirectoryAndSubdirectories(targetPath, &allDeleted);
		if (bRebootRequired)
		{
			std::wcout << L"REBOOT REQUIRED to complete deletion." << std::endl;
		}
	}
	else
	{
		std::wcout << L"Removes (deletes) a directory and all subdirectories." << std::endl;
		std::wcout << std::endl;
		std::wcout << "LONGRMDIR [drive:]path" << std::endl;
		std::wcout << std::endl;
		std::wcout << "Removes all directories and files in the specified directory" << std::endl;
		std::wcout << "in addition to the directory itself. Used to remove a directory" << std::endl;
		std::wcout << "tree." << std::endl;
	}

}
