# AnalyzePdb

解析符号表获取函数偏移。
get function offset by pdb.

*************************************************
*************** write by xuxian *****************
*************************************************


AnalyzePdb.exe analyze_file [[-f] | [-s] | [-l][-s] | [-x]]

analyze_file                             need to analyze file

[-f or -function function_name]          get the function address.
                                         for example: AnalyzePdb.exe 64win7_ntoskrnl.exe -f RtlInitUnicodeString.
[-x function_sign]                       get the function address.
                                         for example: AnalyzePdb.exe 64win7_ntoskrnl.exe -x Rtl*. will get all Rtl function.
[-s or -save file_path]                  save analyze pdb data.
                                         for example: AnalyzePdb.exe 64win7_ntoskrnl.exe -x Rtl* -s Rtl.txt.
[-l or -list list_file_path]             analyze list functions.
                                         for example: AnalyzePdb.exe 64win7_ntoskrnl.exe -l list.txt -s list_function.txt.