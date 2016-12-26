// AnalyzeNtosPdb.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "XX_Symbols.h"

#include <Shlwapi.h>
#include <Psapi.h>

#include <map>
#include <list>
#include <fstream>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define ANSI_COLOR_RED_STRING(_str_) std::string(ANSI_COLOR_RED).append(_str_).append(ANSI_COLOR_RED).c_str()

class AnalyzePdb
{
private:
	typedef struct _FoundInfo 
	{
		bool isFound;
		XX_Symbols::_SYMBOLS_INFO symbolsInfo;
	}FoundInfo;
public:
	AnalyzePdb();
	~AnalyzePdb();
public:
	void getFunction(std::string & vModuleName, std::string & vFuncName);
	void getSaveFunction(std::string & vModuleName, std::string & vSaveName);
	void getListFunction(std::string & vModuleName, std::string & vListName, std::string & vSaveName);
	void getXFunction(const std::string & vModuleName, const std::string & vSign, const std::string & vSaveFile);
private:
	//void saveFile(const std::string & vFileName, const std::vector<std::string> & vVector);
	void saveFile(const std::string & vFileName);
	bool getFile(const std::string & vFileName);
private:
	std::map<std::string, FoundInfo> m_symMap;
};

AnalyzePdb::AnalyzePdb()
{
}

AnalyzePdb::~AnalyzePdb()
{
}

void AnalyzePdb::saveFile(const std::string & vFileName)
{
	std::fstream ifile;
	ifile.open(vFileName, std::ios::app);
	for (auto iter : m_symMap)
	{
		char szTemp[MAX_PATH] = { 0 };
		int len = sprintf_s(szTemp, sizeof(szTemp), "[rva:0x%08x] [file offset:0x%08x] [func: %s] %s\n",
			iter.second.symbolsInfo.FunctionOffset,
			iter.second.symbolsInfo.FileOffset,
			iter.second.symbolsInfo.FunctionName.c_str(),
			iter.second.isFound ? "" : "[!!!! not found !!!!]");

		printf(szTemp);

		if (ifile.is_open())
		{
			ifile.write(szTemp, len);
		}
	}

	if (ifile.is_open())
	{
		ifile.close();
	}
}

bool AnalyzePdb::getFile(const std::string & vFileName)
{
	std::ifstream ifFile;
	ifFile.open(vFileName.c_str());
	if (false == ifFile.is_open())
	{
		printf("can not open file!:%s\n", vFileName.c_str());
		return false;
	}
	
	m_symMap.clear();

	char szName[MAX_PATH] = { 0 };
	std::list<std::string> listVec;
	while (!ifFile.eof())
	{
		ifFile.getline(szName, sizeof(szName));
		m_symMap[szName] = FoundInfo{ false, XX_Symbols::SYMBOLS_INFO{ 0, 0, szName } };
	}

	ifFile.close();
	return true;
}

void AnalyzePdb::getFunction(std::string & vModuleName, std::string & vFuncName)
{
	auto moduleFile = vModuleName;
	auto funcName = vFuncName;

	XX_Symbols xxSymbols;
	XX_Symbols::SYMBOLS_INFO funcInfo = { 0 };
	auto funcAddress = xxSymbols.GetProcAddressOffset(moduleFile.c_str(), funcName.c_str(), &funcInfo);
	if (funcAddress)
	{
		printf("[rva:0x%x] [file offset:0x%x] [func: %s]\n", funcInfo.FunctionOffset, funcInfo.FileOffset, funcName.c_str());
	}
	else
	{
		printf("can not found function: %s\n", funcName.c_str());
	}
}

void AnalyzePdb::getSaveFunction(std::string & vModuleName, std::string & vSaveName)
{
	auto moduleFile = vModuleName;
	
	XX_Symbols xxSymbols;
	std::vector<std::string> vecResult;
	auto symVec = xxSymbols.GetAllProcAddressOffset(moduleFile.c_str());
	if (false == symVec.empty())
	{
		for (auto iter : symVec)
		{
			m_symMap[iter.FunctionName] = FoundInfo{ true, iter };
		}
	}
	else
	{
		printf("save functions fail!\n");
	}
	saveFile(vSaveName);
}

void AnalyzePdb::getListFunction(std::string & vModuleName, std::string & vListName, std::string & vSaveName)
{
	auto moduleFile = vModuleName;
	if (false == getFile(vListName))
	{
		printf("get file fail!\n");
		return;
	}

	XX_Symbols xxSymbols;
	auto symVec = xxSymbols.GetAllProcAddressOffset(moduleFile.c_str());
	if (false == symVec.empty())
	{
		for (auto iter : symVec)
		{
			if (m_symMap.find(iter.FunctionName) != m_symMap.end())
			{
				m_symMap[iter.FunctionName] = FoundInfo{ true, iter };
			}
		}
	}
	saveFile(vSaveName);
}

void AnalyzePdb::getXFunction(const std::string & vModuleName, const std::string & vSign, const std::string & vSaveFile)
{
	std::string sign = vSign;
	std::vector<std::string> vecSign;

	int type = 0;
	std::string signDot = "*";
	if (std::string::npos != sign.find(signDot))
	{
		// type 会有1 ，2 ，3
		if (*sign.begin() == *signDot.begin())
		{
			type |= 1;
		}
		if (*(sign.end() - 1) == *signDot.begin())
		{
			type |= 2;
		}

		std::string tempSign = sign;
		auto pos = tempSign.find(signDot);
		while (std::string::npos != pos)
		{
			tempSign.replace(pos, 1, "");
			pos = tempSign.find(signDot);
		}
		sign = tempSign;
	}
	else
	{
		type = 2;
	}

	bool isFound = false;
	XX_Symbols xxSymbols;
	auto symVec = xxSymbols.GetAllProcAddressOffset(vModuleName.c_str());
	for (auto iter : symVec)
	{
		switch (type)
		{
		case 1:
			if (iter.FunctionName.length() > sign.length())
			{
				std::string temp = iter.FunctionName.substr(iter.FunctionName.length() - sign.length());
				if (temp == sign)
				{
					isFound = true;
				}
			}
			break;
		case 2:
			if (iter.FunctionName.substr(0, sign.length()) == sign)
			{
				isFound = true;
			}
			break;
		case 3:
			if (std::string::npos != iter.FunctionName.find(sign.c_str()))
			{
				isFound = true;
			}
			break;
		default:
			break;
		}
		if (isFound)
		{
			m_symMap[iter.FunctionName] = FoundInfo{ true, iter };
		}
		isFound = false;
	}

	saveFile(vSaveFile);
}

void logo()
{
	printf("\n");
	printf("*************************************************\n");
	printf("*************** write by xuxian *****************\n");
	printf("*************************************************\n");
	printf("\n");
}

void help()
{
#define logformat "%-40s %-40s \n%-40s %s\n"
	char szName[MAX_PATH] = { 0 };
	GetModuleBaseNameA(GetCurrentProcess(), NULL, szName, MAX_PATH);

	printf("\n%s analyze_file [[-f] | [-s] | [-l][-s] | [-x]]\n\n", szName);

	printf(logformat, 
		"analyze_file", 
		"need to analyze file",
		" ",
		"");

	printf(logformat,
		"[-f or -function function_name]",
		"get the function address. ",
		" ",
		"for example: AnalyzePdb.exe 64win7_ntoskrnl.exe -f RtlInitUnicodeString.");

	printf(logformat,
		"[-x function_sign]",
		"get the function address. ",
		" ",
		"for example: AnalyzePdb.exe 64win7_ntoskrnl.exe -x Rtl*. will get all Rtl function.");

	printf(logformat,
		"[-s or -save file_path]",
		"save analyze pdb data. ",
		" ",
		"for example: AnalyzePdb.exe 64win7_ntoskrnl.exe -x Rtl* -s Rtl.txt.");

	printf(logformat,
		"[-l or -list list_file_path]",
		"analyze list functions. ",
		" ",
		"for example: AnalyzePdb.exe 64win7_ntoskrnl.exe -l list.txt -s list_function.txt.");
}


int main(int argv, void* args[])
{
	logo();
	if (argv == 1 || argv % 2)
	{
		help();
		return 0;
	}

	std::string strFile = static_cast<char*>(args[1]);
	if (!PathFileExistsA(strFile.c_str()))
	{
		printf("%s is not exist!", strFile.c_str());
		return 0;
	}

	AnalyzePdb analyze;
	std::map<std::string, std::string> cmdMap;
	for (auto i = 2; i < argv; i += 2)
	{
		std::string strArg = std::string(static_cast<char*>(args[i]));
		if (strArg.empty())
		{
			help();
			return 0;
		}
		
		if (std::string::npos != strArg.find("-f") || std::string::npos != strArg.find("-function"))
		{
			cmdMap["function"] = static_cast<char*>(args[i + 1]);
		}
		if (std::string::npos != strArg.find("-s") || std::string::npos != strArg.find("-save"))
		{
			cmdMap["save"] = static_cast<char*>(args[i + 1]);
		}
		if (std::string::npos != strArg.find("-l") || std::string::npos != strArg.find("-list"))
		{
			cmdMap["list"] = static_cast<char*>(args[i + 1]);
		}
		if (std::string::npos != strArg.find("-x"))
		{
			cmdMap["x"] = static_cast<char*>(args[i + 1]);
		}
	}

	if (false == cmdMap["function"].empty())
	{
		analyze.getFunction(strFile, cmdMap["function"]);
	}
	else if (false == cmdMap["list"].empty())
	{
		analyze.getListFunction(strFile, cmdMap["list"], cmdMap["save"]);
	}
	else if (false == cmdMap["x"].empty())
	{
		analyze.getXFunction(strFile, cmdMap["x"], cmdMap["save"]);
	}
	else if (false == cmdMap["save"].empty())
	{
		analyze.getSaveFunction(strFile, cmdMap["save"]);
	}
	system("pause");
    return 0;
}

