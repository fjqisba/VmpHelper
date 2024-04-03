#pragma once
#include <string>

//copy from source code of x64Dbg

class StringUtils
{
public:
	static std::wstring LocalCpToUtf16(const char* str);
    static std::wstring Utf8ToUnicode(const char* str);
	static std::string Utf16ToUtf8(const wchar_t* wstr);
	static std::string LocalCpToUtf8(const char* str);
	static std::string sprintf(_In_z_ _Printf_format_string_ const char* format, ...);
	static std::string vsprintf(_In_z_ _Printf_format_string_ const char* format, va_list args);
};