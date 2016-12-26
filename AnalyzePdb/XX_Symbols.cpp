#include "stdafx.h"
#include "XX_Symbols.h"

#include <windows.h>
#include <Shlwapi.h>
#include <ImageHlp.h>
#include <Psapi.h>
#include <winnt.h>

#include "md5.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "ImageHlp.lib")
#pragma warning(disable: 4996)

XX_Symbols::XX_Symbols()
{
}


XX_Symbols::~XX_Symbols()
{
}

bool XX_Symbols::EnableDebugPriv(void)
{
	HANDLE hToken;

	LUID sedebugnameValue;

	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return false;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);

		return false;
	}
	tkp.PrivilegeCount = 1;

	tkp.Privileges[0].Luid = sedebugnameValue;

	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		CloseHandle(hToken);

		return false;
	}
	return true;
}

bool XX_Symbols::InitSymbols(void)
{
	if (m_isInit)
	{
		return true;
	}

	std::string strCurDir = GetCurDir();
	if (strCurDir.empty())
	{
		return false;
	}

	auto strFile = std::string(strCurDir).append("symsrv.yes");
	auto hfile = CreateFileA(strFile.c_str(),FILE_ALL_ACCESS,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
	if (hfile == INVALID_HANDLE_VALUE)
	{
		output("CreateFileA fail! %s, error: 0x%X\n", strFile.c_str(), GetLastError());
		return FALSE;
	}
	CloseHandle(hfile);

	EnableDebugPriv();
	SymSetOptions(SYMOPT_CASE_INSENSITIVE | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
	SymCleanup(GetCurrentProcess());

	auto strSymbolsPath = std::string("SRV*").append(strCurDir).append("symbols*http://msdl.microsoft.com/download/symbols");
	if (FALSE == SymInitialize(GetCurrentProcess(), strSymbolsPath.c_str(), FALSE))
	{
		output("SymInitialize fail! %s, error: 0x%X\n", strSymbolsPath.c_str(), GetLastError());
		return false;
	}

	//output("symbols path:%s\n", strSymbolsPath.c_str());
	m_isInit = true;
	return true;
}

BOOL CALLBACK XX_Symbols::EnumSymRoutineAll(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext)
{

	XX_Symbols *pSymbols = (XX_Symbols *)UserContext;	
	if (pSymbols)
	{
		SYMBOLS_INFO symbolsTemp = { 0 };
		symbolsTemp.FunctionOffset = static_cast<ULONG>(pSymInfo->Address - pSymInfo->ModBase);
		symbolsTemp.FunctionName = pSymInfo->Name;
		symbolsTemp.FileOffset = pSymbols->GetFileOffset(symbolsTemp.FunctionOffset);
		pSymbols->GetSymVec().push_back(symbolsTemp);
	}
	return TRUE;
}

bool XX_Symbols::EnumSymbols(void)
{
	const char* moduleFullName = m_moduleFullName.c_str();
	if (false == InitSymbols())
	{
		output("InitSymbols fail!\n");
		return false;
	}

	if (FALSE == PathFileExistsA(moduleFullName))
	{
		output("PathFileExistsA fail! : %s\n", moduleFullName);
		return false;
	}

	char SymFileName[MAX_PATH] = { 0 };
	if (FALSE == SymGetSymbolFile(GetCurrentProcess(), NULL, moduleFullName, sfPdb, SymFileName, MAX_PATH, SymFileName, MAX_PATH))
	{
		output("SymGetSymbolFile fail£º%s, %s, error: 0x%X\n", moduleFullName, SymFileName, GetLastError());
		return false;
	}

	PLOADED_IMAGE pImage = ImageLoad(moduleFullName, "");
	if (nullptr == pImage)
	{
		output("ImageLoad fail£º%s, error: 0x%X\n", moduleFullName, GetLastError());
		ImageUnload(pImage);
		return false;
	}

	if (false == GetSectionItems(pImage))
	{
		output("GetSectionItems fail£º%s, error: 0x%X\n", moduleFullName, GetLastError());
		ImageUnload(pImage);
		return false;
	}

	if (!SymLoadModule64(GetCurrentProcess(), pImage->hFile, moduleFullName, NULL, reinterpret_cast<DWORD64>(pImage->MappedAddress), pImage->SizeOfImage))
	{
		output("SymLoadModule64£º0x%X\n", GetLastError());
		ImageUnload(pImage);
		return false;
	}

	if (FALSE == SymEnumSymbols(GetCurrentProcess(), reinterpret_cast<DWORD64>(pImage->MappedAddress), NULL, XX_Symbols::EnumSymRoutineAll, this))
	{
		output("SymEnumSymbols£º0x%X\n", GetLastError());
		ImageUnload(pImage);
		return false;
	}

	ImageUnload(pImage);
	return true;
}

bool XX_Symbols::GetSectionItems(PVOID ImageBase)
{
	PLOADED_IMAGE imageLoad = static_cast<PLOADED_IMAGE>(ImageBase);
	PIMAGE_NT_HEADERS pNt = ImageNtHeader(imageLoad->MappedAddress);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	if (pNt && pSec)
	{
		for (WORD i = 0; i != pNt->FileHeader.NumberOfSections; i++)
		{
			//printf("%d, VirtualAddress:0x%x, 0x%x\n", i, pSec[i].VirtualAddress, pSec[i].PointerToRawData);
			m_sectionVec.push_back({ pSec[i].VirtualAddress, pSec[i].PointerToRawData });
		}
	}
	return true;
}

std::string XX_Symbols::GetModuleMd5(void)
{
	const char* moduleFullName = m_moduleFullName.c_str();
	
	PLOADED_IMAGE imageLoad = ImageLoad(moduleFullName, "");
	if (nullptr == imageLoad)
	{
		return "";
	}

	unsigned char szMd5[16] = { 0 };
	MD5_CTX md5Ctx;
	md5Ctx.MD5Update((unsigned char*)imageLoad->MappedAddress, (unsigned int)imageLoad->SizeOfImage);
	md5Ctx.MD5Final(szMd5);

	ImageUnload(imageLoad);

	std::string strMd5 = "";
	for (auto i = 0; i < 16; i++)
	{
		char szCh[4] = { 0 };
		sprintf_s(szCh, sizeof(szCh), "%02x", szMd5[i]);
		strMd5.append(szCh);
	}

	return strMd5;
}

std::string XX_Symbols::GetCurDir()
{
	char szFileName[MAX_PATH] = { 0 };
	GetModuleFileNameA(nullptr, szFileName, MAX_PATH);

	std::string strFileName = std::string(szFileName);
	if (strFileName.empty())
	{
		output("GetModuleFileNameA fail! 0x%x\n", GetLastError());
	}
	
	auto strPos = strFileName.find_last_of('\\');
	if (std::string::npos == strPos)
	{
		output("GetCurDir find_last_of fail!");
	}

	return strFileName.substr(0, strPos + 1);
}

const ULONG XX_Symbols::GetProcAddressOffset(const char* vModuleFullName, const char* vFunctionName, PSYMBOLS_INFO vSymbolsInfo)
{
	SymVec tempSymVec = GetAllProcAddressOffset(vModuleFullName);
	if (tempSymVec.empty())
	{
		return 0;
	}

	ULONG funcAddress = 0;
	for (auto iter = tempSymVec.begin(); iter != tempSymVec.end(); ++iter)
	{
		if (iter->FunctionName == std::string(vFunctionName))
		{
			funcAddress = iter->FileOffset;
			if (vSymbolsInfo)
			{
				*vSymbolsInfo = *iter;
			}
			break;
		}
	}

	return funcAddress;
}

const ULONG XX_Symbols::GetProcAddressOffset(const char* vModuleFullName, const char* vFunctionName)
{	
	return GetProcAddressOffset(vModuleFullName, vFunctionName, nullptr);
}

const XX_Symbols::SymVec XX_Symbols::GetAllProcAddressOffset(const char* vModuleFullName)
{
	m_moduleFullName = vModuleFullName;

	SymVec tempSymVec;
	std::string strMd5 = GetModuleMd5();
	if (strMd5.empty())
	{
		output("GetModuleMd5 fail!\n");
		return tempSymVec;
	}

	if (m_symMap.end() != m_symMap.find(strMd5))
	{
		tempSymVec = m_symMap[strMd5];
	}
	else
	{
		printf("loading symbols, wait...\n\n");
		if (false == EnumSymbols())
		{
			output("EnumSymbols fail!\n");
			return tempSymVec;
		}
		tempSymVec = m_symVec;
		m_symMap.insert(std::make_pair(strMd5, m_symVec));
	}
	return tempSymVec;
}

const ULONG XX_Symbols::GetFileOffset(ULONG vRva)
{
	for (SectionVec::iterator iter = m_sectionVec.begin(); iter != m_sectionVec.end(); iter++)
	{
		if (vRva <= iter->VOffset)
		{
			return vRva - (iter->VOffset - iter->ROffset);
		}
	}
	return 0;
}