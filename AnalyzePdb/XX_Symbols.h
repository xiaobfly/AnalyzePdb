#pragma once

#include <windows.h>
#include <vector>
#include <map>
#include <string>

#define openlog

#ifdef openlog
#define output printf
#else
#define output
#endif // openlog


typedef struct _SYMBOL_INFO *PSYMBOL_INFO;

class XX_Symbols
{
public:
	struct _SYMBOLS_INFO
	{
		ULONG FileOffset;
		ULONG FunctionOffset;
		std::string FunctionName;
	};

	typedef _SYMBOLS_INFO SYMBOLS_INFO, *PSYMBOLS_INFO;
	typedef std::vector<SYMBOLS_INFO> SymVec;
	typedef std::map<std::string, SymVec> SymMap;
private:
	struct _SECTION_ITEM
	{
		ULONG VOffset;//节点RVA
		ULONG ROffset;//节点FileOffset
	};
	typedef _SECTION_ITEM SECTION_ITEM, *PSECTION_ITEM;
	typedef std::vector<SECTION_ITEM> SectionVec;
public:
	XX_Symbols();
	~XX_Symbols();

public:
	const ULONG	GetProcAddressOffset(const char* vModuleFullName, const char* vFunctionName);
	const ULONG	GetProcAddressOffset(const char* vModuleFullName, const char* vFunctionName, PSYMBOLS_INFO vSymbolsInfo);
	const SymVec GetAllProcAddressOffset(const char* vModuleFullName);
	const ULONG GetFileOffset(ULONG vRva);

private:
	bool EnableDebugPriv(void);
	bool InitSymbols(void);
	bool EnumSymbols(void);
	bool GetSectionItems(PVOID ImageBase);
	
	std::string GetModuleMd5(void);
	std::string GetCurDir();

	static BOOL CALLBACK EnumSymRoutineAll(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext);
public:
	SymVec& GetSymVec() { return m_symVec; }
private:
	SymVec m_symVec;
	SymMap m_symMap;
	SectionVec m_sectionVec;
	std::string m_moduleFullName;
	bool m_isInit = false;
};

