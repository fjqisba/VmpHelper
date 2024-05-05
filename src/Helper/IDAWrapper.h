#pragma once
#include <string>
#include <vector>

class IDAWrapper
{
public:
    static void show_wait_box(const char* msg);
    static void hide_wait_box();
    static int get_bytes(void* buf, unsigned int size, unsigned int ea, int gmb_flags = 0, void* mask = nullptr);
    static std::uint32_t get_dword(size_t ea);
    static std::uint16_t get_word(size_t ea);
    static std::string get_shortstring(size_t addr);
    static std::string idadir(const char* subdir);

    static void setFuncName(size_t addr, const char* funcName, bool bForce = true);
    static void set_cmt(size_t ea, const char* comm, bool rptble = true);
    static std::string get_cmt(size_t ea);
    static void msg(const char* format, ...);
    static bool apply_cdecl(unsigned int ea, const char* decl, int flags = 0);

    static std::vector<unsigned int> getAllCodeXrefAddr(unsigned int addr);

    static bool add_user_stkpnt(unsigned int ea, int delta);

    //枚举指定目录文件
    static std::vector<std::string> enumerate_files(const char* dir, const char* fname);

    //获取输入的文件路径
    static std::string get_input_file_path();

    //获取输入文件的MD5
    static std::string get_input_file_md5();

    static bool is64BitProgram();

	static bool isVmpEntry(size_t startAddr);
};
