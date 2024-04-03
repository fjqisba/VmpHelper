#include "StringUtils.h"
#include <windows.h>
#include <vector>

std::wstring StringUtils::Utf8ToUnicode(const char* str)
{
    std::wstring convertedString;
    if (!str || !*str)
        return convertedString;
    int requiredSize = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
    if (requiredSize > 0)
    {
        convertedString.resize(requiredSize - 1);
        if (!MultiByteToWideChar(CP_UTF8, 0, str, -1, (wchar_t*)convertedString.c_str(), requiredSize))
            convertedString.clear();
    }
    return convertedString;
}

std::wstring StringUtils::LocalCpToUtf16(const char* str)
{
	std::wstring convertedString;
	if (!str || !*str)
		return convertedString;
	int requiredSize = MultiByteToWideChar(CP_ACP, 0, str, -1, nullptr, 0);
	if (requiredSize > 0)
	{
		convertedString.resize(requiredSize - 1);
		if (!MultiByteToWideChar(CP_ACP, 0, str, -1, (wchar_t*)convertedString.c_str(), requiredSize))
			convertedString.clear();
	}
	return convertedString;
}

std::string StringUtils::Utf16ToUtf8(const wchar_t* wstr)
{
	std::string convertedString;
	if (!wstr || !*wstr)
		return convertedString;
	auto requiredSize = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
	if (requiredSize > 0)
	{
		convertedString.resize(requiredSize - 1);
		if (!WideCharToMultiByte(CP_UTF8, 0, wstr, -1, (char*)convertedString.c_str(), requiredSize, nullptr, nullptr))
			convertedString.clear();
	}
	return convertedString;
}

std::string StringUtils::LocalCpToUtf8(const char* str)
{
	return Utf16ToUtf8(LocalCpToUtf16(str).c_str());
}

std::string StringUtils::sprintf(_In_z_ _Printf_format_string_ const char* format, ...)
{
	va_list args;
	va_start(args, format);
	auto result = vsprintf(format, args);
	va_end(args);
	return result;
}

std::string StringUtils::vsprintf(_In_z_ _Printf_format_string_ const char* format, va_list args)
{
	char sbuffer[64] = "";
	if (_vsnprintf_s(sbuffer, _TRUNCATE, format, args) != -1)
		return sbuffer;
	std::vector<char> buffer(256, '\0');
	while (true)
	{
		int res = _vsnprintf_s(buffer.data(), buffer.size(), _TRUNCATE, format, args);
		if (res == -1){
			buffer.resize(buffer.size() * 2);
			continue;
		}
		else
			break;
	}
	return std::string(buffer.data());
}