#include "IDAWrapper.h"
#include <pro.h>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <frame.hpp>
#include <sstream>
#include <iomanip>

void IDAWrapper::show_wait_box(const char* msg)
{
    ::show_wait_box("%s", msg);
}

void IDAWrapper::hide_wait_box()
{
    ::hide_wait_box();
}

int IDAWrapper::get_bytes(void* buf, unsigned int size, unsigned int ea, int gmb_flags /*= 0*/, void* mask /*= nullptr*/)
{
    return ::get_bytes(buf, size, ea, gmb_flags, mask);
}

std::uint32_t IDAWrapper::get_dword(size_t ea)
{
    return ::get_dword(ea);
}

std::uint16_t IDAWrapper::get_word(size_t ea)
{
    return ::get_word(ea);
}

std::string IDAWrapper::get_shortstring(size_t addr)
{
    if (addr <= 0){
        return "";
    }
    char buffer[255] = { 0 };
    //没读取到完整的字节应该算是错误了
    if (get_bytes(buffer, sizeof(buffer), addr, GMB_READALL, NULL) != sizeof(buffer)){
        return "";
    }
    std::string ret = buffer;
    return ret;
}

std::string IDAWrapper::idadir(const char* subdir)
{
    std::string retDir = ::idadir(subdir);
    return retDir;
}

void IDAWrapper::set_cmt(size_t ea, const char* comm, bool rptble)
{
    ::set_cmt(ea, comm, rptble);
}

std::string IDAWrapper::get_cmt(size_t ea)
{
    std::string comment;
    qstring tmpCmt;
    ::get_cmt(&tmpCmt, ea, false);
    if (!tmpCmt.empty()) {
        comment.assign(tmpCmt.c_str(), tmpCmt.length());
    }
    return comment;
}

void IDAWrapper::setFuncName(size_t addr, const char* funcName, bool bForce /*= true*/)
{
    if (!bForce) {
        qstring oldName = ::get_name(addr);
        if (oldName.find("sub_") == qstring::npos) {
            return;
        }
    }
    qstring newName;
    acp_utf8(&newName, funcName);
    set_name(addr, newName.c_str(), SN_NOWARN | SN_FORCE);
}

void IDAWrapper::msg(const char* format, ...)
{
    va_list va;
    va_start(va, format);
    int nbytes = vmsg(format, va);
    va_end(va);
    return;
}

bool IDAWrapper::apply_cdecl(unsigned int ea, const char* decl, int flags /*= 0*/)
{
    til_t* idati = (til_t*)get_idati();
    if (!idati) {
        return false;
    }
    return ::apply_cdecl(idati, ea, decl, flags);
}

std::vector<unsigned int> IDAWrapper::getAllCodeXrefAddr(unsigned int addr)
{
    std::vector<unsigned int> retXrefList;
    auto XrefAddr = get_first_cref_to(addr);
    while (XrefAddr != BADADDR)
    {
        retXrefList.push_back(XrefAddr);
        XrefAddr = get_next_cref_to(addr, XrefAddr);
    }
    return retXrefList;
}

bool IDAWrapper::add_user_stkpnt(unsigned int ea, int delta)
{
    return ::add_user_stkpnt(ea, delta);
}

std::vector<std::string> IDAWrapper::enumerate_files(const char* dir, const char* fname)
{
    std::vector<std::string> retFileList;
    struct MyFileEnumerator :public file_enumerator_t
    {
    public:
        std::vector<std::string>& fileList;
        MyFileEnumerator(std::vector<std::string>& f) :fileList(f) {};
        int visit_file(const char* file)
        {
            fileList.push_back(file);
            return 0;
        }
    };
    MyFileEnumerator fileEnumFunc(retFileList);
    enumerate_files2(0, 0, dir, fname, fileEnumFunc);
    return retFileList;
}

std::string IDAWrapper::get_input_file_path()
{
    char file_path[MAXSTR];
    if (!::get_input_file_path(file_path, sizeof(file_path))){
        return "";
    }
    return file_path;
}

std::string IDAWrapper::get_input_file_md5()
{
    uchar buff[16] = { 0 };
    if (!retrieve_input_file_md5(buff)) {
        return "";
    }
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (int i = 0; i < 16; ++i) {
		ss << std::setw(2) << static_cast<int>(buff[i]);
	}
	return ss.str();
}

bool IDAWrapper::is64BitProgram()
{
    return inf_is_64bit();
}

bool IDAWrapper::isVmpEntry(size_t startAddr)
{
	if (IDAWrapper::get_cmt(startAddr) == "vmp entry") {
		return true;
	}
	return false;
}