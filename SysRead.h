#ifndef NATIVESURFACE_MEMREAD_H
#define NATIVESURFACE_MEMREAD_H

#include <algorithm>
#include <arpa/inet.h>
#include <codecvt>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h> 
#include <fstream>
#include <iostream>
#include <locale>
#include <malloc.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <thread>
#include <unistd.h>
#include <vector>

// ========== DriverMemory.h 驱动适配层 ==========
#include "DriverMemory.h"

// 驱动指针（在main.cpp中初始化，内核模块加载后赋值）
// dr 由 DriverMemory.h extern 声明，在 draw_Gui.cpp 定义

// 辅助宏：检查驱动是否就绪
inline bool driver_ready() {
    return dr.IsConnected();
}


	// 定义圆周率
#define PI 3.141592653589793238
typedef unsigned int ADDRESS;
typedef char PACKAGENAME;
typedef unsigned short UTF16;
typedef char UTF8;
#define UNI_SUR_HIGH_START (UTF32)0xD800
#define UNI_SUR_HIGH_END (UTF32)0xDBFF
#define UNI_SUR_LOW_START (UTF32)0xDC00
#define UNI_SUR_LOW_END (UTF32)0xDFFF
	// Some fundamental constants
#define UNI_REPLACEMENT_CHAR (UTF32)0x0000FFFD
#define UNI_MAX_BMP (UTF32)0x0000FFFF
#define UNI_MAX_UTF16 (UTF32)0x0010FFFF
#define UNI_MAX_UTF32 (UTF32)0x7FFFFFFF
#define UNI_MAX_LEGAL_UTF32 (UTF32)0x0010FFFF
#define _PROCESS_VM_READV 270
#define _PROCESS_VM_WRITEV 271


int pid, getPID(char bm[64]), count, ipid, oid, scwz, location,Detect;
float px,py;
unsigned long Starting_address = 0x0000000000000000;
unsigned long End_Address = 0x7fffffffffffffff;

int Data_type = 1;
int 处理内存;


// ========== DriverMemory.h 驱动适配：进程读写内存 ==========
// 所有读写操作现在统一通过 Driver 类的共享内存通信实现

// 读取内存 (通过驱动)
inline bool vm_readv(unsigned long address, void *buffer, size_t size)
{
    if (!driver_ready()) return false;
    return dr.Read(address, buffer, size) > 0;
}

// 写入内存 (通过驱动)
inline bool vm_writev(unsigned long address, void *buffer, size_t size)
{
    if (!driver_ready()) return false;
    return dr.Write(address, buffer, size) > 0;
}

// ========== 驱动适配版读写辅助函数 ==========
// 所有函数现在统一通过 Driver 类操作，不再需要 Data_type 分支

// 获取F类内存
inline float getfloat(unsigned long addr)
{
    if (!driver_ready()) return 0.0f;
    return dr.Read<float>(addr);
}

inline float getFloat(unsigned long addr)
{
    if (!driver_ready()) return 0.0f;
    return dr.Read<float>(addr);
}

// 获取D类内存
inline int getdword(unsigned long addr)
{
    if (!driver_ready()) return 0;
    return dr.Read<int>(addr);
}

inline int getDword(unsigned long addr)
{
    if (!driver_ready()) return 0;
    return dr.Read<int>(addr);
}

// 获取指针(32位游戏)
inline unsigned int getPtr32(unsigned int addr)
{
    if (addr == 0 || !driver_ready()) return 0;
    return dr.Read<unsigned int>(addr);
}

// 获取指针(64位游戏)
inline unsigned long getPtr64(unsigned long addr)
{
    if (!driver_ready()) return 0;
    return dr.Read<unsigned long>(addr);
}

// 获取指针(64位游戏) 无过缺页
inline unsigned long getPtr641(unsigned long addr)
{
    if (!driver_ready()) return 0;
    return dr.Read<unsigned long>(addr);
}

// 写入D类内存
inline void writedword(unsigned long addr, int data)
{
    if (!driver_ready()) return;
    dr.Write<int>(addr, data);
}

// 写入F类内存
inline void writefloat(unsigned long addr, float data)
{
    if (!driver_ready()) return;
    dr.Write<float>(addr, data);
}


// 获取进程
int getPID(const char *packageName)
{
	int id = -1;
	DIR *dir;
	FILE *fp;
	char filename[64];
	char cmdline[64];
	struct dirent *entry;
	dir = opendir("/proc");
	while ((entry = readdir(dir)) != NULL)
	{
		id = atoi(entry->d_name);
		if (id != 0)
		{
			sprintf(filename, "/proc/%d/cmdline", id);
			fp = fopen(filename, "r");
			if (fp)
			{
				fgets(cmdline, sizeof(cmdline), fp);
				fclose(fp);
				if (strcmp(packageName, cmdline) == 0)
				{
					return id;
				}
			}
		}
	}
	closedir(dir);
	return -1;
}

// 获取可执行段的基地址（draw_gui版本）- 查找可执行段
unsigned long getExecutableBaseAddress(int pid, const char *module_name) {
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    FILE *fp = fopen(maps_path.c_str(), "r");
    if (!fp) return 0;
    
    char line[1024];
    unsigned long exec_base_addr = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module_name) != NULL) {
            // 检查是否为可执行段
            if (strstr(line, "r-xp") != NULL || strstr(line, "rwxp") != NULL || 
                (strlen(line) > 10 && line[4] == 'x')) {
                char *dash = strchr(line, '-');
                if (dash) {
                    *dash = '\0';
                    exec_base_addr = strtoull(line, NULL, 16);
                    break;
                }
            }
        }
    }
    
    fclose(fp);
    return exec_base_addr;
}

// 保留原来的get_module_base函数作为兼容
unsigned long get_module_base(int pid, const char *module_name)
{
    // 调用新的可执行段获取函数
    return getExecutableBaseAddress(pid, module_name);
}

// 获取模块基地址（兼容旧版本）- 返回第一个匹配的段
unsigned long getModuleBaseAddress(int pid, const char *module_name)
{
    FILE *fp;
    unsigned long addr = 0;
    char *pch;
    char filename[64];
    char line[1024];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if (fp != NULL)
    {
        while (fgets(line, sizeof(line), fp))
        {
            if (strstr(line, module_name))
            {
                pch = strtok(line, "-");
                addr = strtoul(pch, NULL, 16);
                if (addr == 0x8000)
                    addr = 0;
                break;
            }
        }
        fclose(fp);
    }
    return addr;
}

// 获取进程是否运行
int isapkrunning(PACKAGENAME * bm)
{
	DIR *dir = NULL;
	struct dirent *ptr = NULL;
	FILE *fp = NULL;
	char filepath[64];
	char filetext[64];
	dir = opendir("/proc/");
	if (dir != NULL)
	{
		while ((ptr = readdir(dir)) != NULL)
		{
			if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0))
				continue;
			if (ptr->d_type != DT_DIR)
				continue;
			sprintf(filepath, "/proc/%s/cmdline", ptr->d_name);
			fp = fopen(filepath, "r");
			if (NULL != fp)
			{
				fgets(filetext, sizeof(filetext), fp);
				if (strcmp(filetext, bm) == 0)
				{
					closedir(dir);
					return 1;
				}
				fclose(fp);
			}
		}
	}
	closedir(dir);
	return 0;
}

// 读取字符信息 (通过驱动)
inline void getUTF8(UTF8 * buf, unsigned long namepy)
{
    if (!driver_ready()) return;
    // 直接通过驱动读取UTF16并转换为UTF8
    char16_t buf16[16] = { 0 };
    dr.Read(namepy, buf16, 28);  // 读取28字节 = 14个UTF16字符

    char16_t* pTempUTF16 = buf16;
    UTF8* pTempUTF8 = buf;
    UTF8* pUTF8End = pTempUTF8 + 32;
    while (pTempUTF16 < pTempUTF16 + 28)
    {
        if (*pTempUTF16 <= 0x007F && pTempUTF8 + 1 < pUTF8End)
        {
            *pTempUTF8++ = (UTF8) * pTempUTF16;
        }
        else if (*pTempUTF16 >= 0x0080 && *pTempUTF16 <= 0x07FF && pTempUTF8 + 2 < pUTF8End)
        {
            *pTempUTF8++ = (*pTempUTF16 >> 6) | 0xC0;
            *pTempUTF8++ = (*pTempUTF16 & 0x3F) | 0x80;
        }
        else if (*pTempUTF16 >= 0x0800 && *pTempUTF16 <= 0xFFFF && pTempUTF8 + 3 < pUTF8End)
        {
            *pTempUTF8++ = (*pTempUTF16 >> 12) | 0xE0;
            *pTempUTF8++ = ((*pTempUTF16 >> 6) & 0x3F) | 0x80;
            *pTempUTF8++ = (*pTempUTF16 & 0x3F) | 0x80;
        }
        else
        {
            break;
        }
        pTempUTF16++;
    }
}

inline int DecryptTssSdtIntSlot64(uintptr_t slotPtr) {
    if (!slotPtr || !driver_ready()) return 0;

    uintptr_t m_value_ptr = getPtr64(slotPtr + 0x10);
    if (!m_value_ptr) return 0;

    int m_xor_key = getDword(slotPtr + 0x18);
    int m_index = getDword(slotPtr + 0x1C);
    int arrayLength = getDword(m_value_ptr + 0x18);

    if (m_index < 0 || m_index >= arrayLength) return 0;

    int encryptedValue = getDword(m_value_ptr + 0x20 + m_index * 4);
    return m_xor_key ^ encryptedValue;
}

// 通用UTF16字符串读取函数 (通过驱动)
inline std::string readUTF16StringFromStruct(uintptr_t struct_addr) {
    if (struct_addr == 0 || !driver_ready()) return "";

    // 读取字符串长度（偏移0x10）
    int str_length = dr.Read<int>(struct_addr + 0x10);

    if (str_length <= 0 || str_length > 100) {
        return "";
    }

    // UTF16字符串从偏移0x14开始
    uintptr_t utf16_str_addr = struct_addr + 0x14;

    std::string result;

    // 读取UTF16字符串
    for (int i = 0; i < str_length; i++) {
        uint16_t utf16_char = dr.Read<uint16_t>(utf16_str_addr + (i * 2));
        if (utf16_char == 0) break;

        // UTF16转UTF8
        if (utf16_char <= 0x7F) {
            result += (char)utf16_char;
        } else if (utf16_char <= 0x7FF) {
            result += (char)(0xC0 | (utf16_char >> 6));
            result += (char)(0x80 | (utf16_char & 0x3F));
        } else {
            result += (char)(0xE0 | (utf16_char >> 12));
            result += (char)(0x80 | ((utf16_char >> 6) & 0x3F));
            result += (char)(0x80 | (utf16_char & 0x3F));
        }
    }

    return result;
}

void 绘制字体描边(float size,int x, int y, ImVec4 color, const char* str)
{
    ImGui::GetBackgroundDrawList()->AddText(NULL, size,ImVec2(x + 1, y), ImGui::ColorConvertFloat4ToU32(ImVec4(0.0f, 0.0f, 0.0f, 1.0f)), str);
    ImGui::GetBackgroundDrawList()->AddText(NULL, size,ImVec2(x - 0.1, y), ImGui::ColorConvertFloat4ToU32(ImVec4(0.0f, 0.0f, 0.0f, 1.0f)), str);
    ImGui::GetBackgroundDrawList()->AddText(NULL, size,ImVec2(x, y + 1), ImGui::ColorConvertFloat4ToU32(ImVec4(0.0f, 0.0f, 0.0f, 1.0f)), str);
    ImGui::GetBackgroundDrawList()->AddText(NULL, size,ImVec2(x, y - 1), ImGui::ColorConvertFloat4ToU32(ImVec4(0.0f, 0.0f, 0.0f, 1.0f)), str);
    ImGui::GetBackgroundDrawList()->AddText(NULL, size,ImVec2(x, y), ImGui::ColorConvertFloat4ToU32(color), str);
}
ImColor 浅蓝 = ImColor(ImVec4(36/255.f, 249/255.f, 217/255.f, 255/255.f));
ImColor 蓝色 = ImColor(ImVec4(170/255.f, 203/255.f, 244/255.f, 0.95f));
ImColor 白色 = ImColor(ImVec4(255/255.f, 255/255.f, 258/255.f, 0.95f));
ImColor 浅粉 = ImColor(ImVec4(255/255.f, 200/255.f, 250/255.f, 0.95f));
ImColor 黑色 = ImColor(ImVec4(0/255.f, 0/255.f, 0/255.f, 0.7f));
ImColor 半黑 = ImColor(ImVec4(0/255.f, 0/255.f, 0/255.f, 0.18f));
ImColor 血色 = ImColor(ImVec4(0/255.f, 249/255.f, 0/255.f, 0.35f));
ImColor 红色 = ImColor(ImVec4(233/255.f, 55/255.f, 51/255.f, 0.95f));
ImColor 绿色 = ImColor(ImVec4(50/255.f, 222/215.f, 50/255.f, 0.95f));
ImColor 黄色 = ImColor(ImVec4(255/255.f, 255/255.f, 0/255.f, 0.95f));
ImColor 橘黄 = ImColor(ImVec4(255/255.f, 150/255.f, 30/255.f, 0.95f));
ImColor 紫色 = ImColor(ImVec4(169/255.f, 120/255.f, 223/255.f, 0.95f));
ImColor 青绿 = ImColor(ImVec4(145/255.f,232/255.f,135/255.f,255/255.f));
ImColor 空白 = ImColor(ImVec4(1.0/255.f, 1.0/255.f, 1.0/255.f, 0.0f));
ImColor 粉红 = ImVec4(1.0f, 0.5f, 0.5f, 1.0f);
ImColor 品红 = ImColor(255,0,255);
#endif

struct Vector2A
{
    float X;
    float Y;

    Vector2A()
    {
        this->X = 0;
        this->Y = 0;
    }

    Vector2A(float x, float y)
    {
        this->X = x;
        this->Y = y;
    }
};

struct D2DVector
{
    float X;
    float Y;
};

struct D3DVector
{
    float X;
    float Y;
    float Z;
};

struct Vector3A
{
    float X;
    float Y;
    float Z;

    Vector3A()
    {
        this->X = 0;
        this->Y = 0;
        this->Z = 0;
    }

    Vector3A(float x, float y, float z)
    {
        this->X = x;
        this->Y = y;
        this->Z = z;
    }
};


float g_ViewMatrix[16];
// 修改 WorldToScreen 函数，移除所有 printf
Vector2A WorldToScreen(Vector3A worldPos) {
    float clipX = g_ViewMatrix[0] * worldPos.X + g_ViewMatrix[4] * worldPos.Y + g_ViewMatrix[8] * worldPos.Z + g_ViewMatrix[12];
    float clipY = g_ViewMatrix[1] * worldPos.X + g_ViewMatrix[5] * worldPos.Y + g_ViewMatrix[9] * worldPos.Z + g_ViewMatrix[13];
    float clipZ = g_ViewMatrix[2] * worldPos.X + g_ViewMatrix[6] * worldPos.Y + g_ViewMatrix[10] * worldPos.Z + g_ViewMatrix[14];
    float clipW = g_ViewMatrix[3] * worldPos.X + g_ViewMatrix[7] * worldPos.Y + g_ViewMatrix[11] * worldPos.Z + g_ViewMatrix[15];
    
    if (clipW <= 0.0001f) return Vector2A(-1, -1);
    
    float ndcX = clipX / clipW;
    float ndcY = clipY / clipW;
    
    float screenX = (ndcX * 0.5f + 0.5f) * abs_ScreenX;
    float screenY = (0.5f - ndcY * 0.5f) * abs_ScreenY;
//    printf("%d\n%d",abs_ScreenX,abs_ScreenY);
    return Vector2A(screenX, screenY);
}

#include <cstdint>

constexpr double FScalarScale = 4294967296.0;  // 2^32

// 加密：float → FScalar (有符号64位整数)
inline int64_t FloatToFScalar(float f)
{
    return static_cast<int64_t>(static_cast<double>(f) * FScalarScale);
}

// 解密：FScalar → float
inline float FScalarToFloat(int64_t fs)
{
    return static_cast<float>(static_cast<double>(fs) / FScalarScale);
}

// 在文件顶部，其他函数之前添加
static ImVec4 HueToRGB(float h) {
    float r = fabs(h * 6.0f - 3.0f) - 1.0f;
    float g = 2.0f - fabs(h * 6.0f - 2.0f);
    float b = 2.0f - fabs(h * 6.0f - 4.0f);
    return ImVec4(
        std::max(0.0f, std::min(1.0f, r)),
        std::max(0.0f, std::min(1.0f, g)),
        std::max(0.0f, std::min(1.0f, b)),
        1.0f
    );
}