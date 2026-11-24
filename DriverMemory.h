#pragma once
#include <cstdio>
#include <sys/mman.h>
#include <cerrno>
#include <cstring> 
#include <atomic>
#include <thread>
#include <mutex>
#include <sys/prctl.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <list>  
#include <thread>
#include <atomic>
#include <memory>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <map>
#include <sstream>
#include <fstream>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <elf.h>

#define PAGE_SIZE 4096
// 读写模式选择：1=简单稳定模式（推荐，不闪框），0=原复杂模式（可能闪框）
#ifndef USE_SIMPLE_RW
#define USE_SIMPLE_RW 0
#endif
// 辅助函数：检查字符串是否以指定后缀结尾 (C++17兼容)
inline bool ends_with(const std::string& str, const std::string& suffix) {
    if (str.length() < suffix.length()) return false;
    return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}

inline bool ends_with(std::string_view str, std::string_view suffix) {
    if (str.length() < suffix.length()) return false;
    return str.substr(str.length() - suffix.length()) == suffix;
}

// 辅助打印函数 (替代 std::println) - 修复格式字符串警告
template<typename... Args>
void print_stderr(const char* format, Args... args) {
    std::fprintf(stderr, format, args...);
}

// 无参数版本 - 直接打印字符串
inline void print_stderr(const char* str) {
    std::fputs(str, stderr);
}

template<typename... Args>
void print_stdout(const char* format, Args... args) {
    std::fprintf(stdout, format, args...);
}

inline void print_stdout(const char* str) {
    std::fputs(str, stdout);
}

__attribute__((noinline))
__attribute__((optimize("-fno-reorder-blocks,-fno-reorder-functions")))
class Driver
{
public:
    Driver(bool touch)
    {
        InitCommunication();
        if (touch)
        {
            InitTouch();
        }
    }

    ~Driver()
    {
    }

bool IsConnected() const { return req != nullptr; }
public:
    class SpinLock
    {
        std::atomic_flag locked = ATOMIC_FLAG_INIT;

        inline void pause() const noexcept
        {
            __builtin_arm_yield();
        }

    public:
        void lock() noexcept
        {
            for (int i = 0; i < 64; ++i)
            {

                if (!locked.test_and_set(std::memory_order_acquire))
                {
                    return;
                }

                while (locked.test(std::memory_order_relaxed))
                {
                    pause();
                }
            }

            while (locked.test_and_set(std::memory_order_acquire))
            {
                locked.wait(true, std::memory_order_relaxed);
            }
        }

        void unlock() noexcept
        {
            locked.clear(std::memory_order_release);
            locked.notify_one();
        }
    };
    SpinLock m_mutex;

    enum bp_type
    {
        BP_READ,
        BP_WRITE,
        BP_READ_WRITE,
        BP_EXECUTE
    } __attribute__((packed));

    enum bp_scope
    {
        SCOPE_MAIN_THREAD,
        SCOPE_OTHER_THREADS,
        SCOPE_ALL_THREADS
    } __attribute__((packed));

struct hwbp_record
{
    bool rw;
    uint64_t pc;        // 触发断点的汇编指令地址
    uint64_t hit_count; // 该 PC 命中的次数
    uint64_t regs[30];  // 最新的 X0 ~ X29 寄存器
    uint64_t lr;        // X30
    uint64_t sp;        // Stack Pointer
    uint64_t orig_x0;   // 原始 X0
    uint64_t syscallno; // 系统调用号
    uint64_t pstate;    // 处理器状态
    __uint128_t vregs[32]; // V0 ~ V31 (每个128位)
    uint32_t fpsr;         // 浮点状态寄存器
    uint32_t fpcr;         // 浮点控制寄存器
    uint64_t reg_modify_mask;  // bit0=X0, bit1=X1, ..., bit29=X29, bit30=LR, bit31=SP, bit32=PC
    uint64_t fp_modify_mask;   // bit0=V0, bit1=V1, ..., bit31=V31
    uint64_t new_pc;
    
} __attribute__((packed));

    struct hwbp_info
    {
        uint64_t num_brps;
        uint64_t num_wrps;
        uint64_t hit_addr;
        int record_count;
        struct hwbp_record records[0x100];
    } __attribute__((packed));

#define MAX_MODULES 512
#define MAX_SCAN_REGIONS 4096

#define MOD_NAME_LEN 256
#define MAX_SEGS_PER_MODULE 256

    struct segment_info
    {
        short index;
        uint8_t prot;
        uint64_t start;
        uint64_t end;
    } __attribute__((packed));

    struct module_info
    {
        char name[MOD_NAME_LEN];
        int seg_count;
        struct segment_info segs[MAX_SEGS_PER_MODULE];
    } __attribute__((packed));

    struct region_info
    {
        uint64_t start;
        uint64_t end;
    } __attribute__((packed));

    struct memory_info
    {
        int module_count;
        struct module_info modules[MAX_MODULES];
        int region_count;
        struct region_info regions[MAX_SCAN_REGIONS];
    } __attribute__((packed));

    enum sm_req_op
    {
        op_o,
        op_r,
        op_w,
        op_m,

        op_down,
        op_move,
        op_up,
        op_init_touch,

        op_brps_weps_info,
        op_set_process_hwbp,
        op_set_process_hwbp_emu,
        op_remove_process_hwbp,

        op_hide_pid_add,
        op_hide_pid_remove,

        op_kexit
    } __attribute__((packed));

    struct req_obj
    {
        std::atomic<int> kernel;
        std::atomic<int> user;
        enum sm_req_op op;
        int status;
        int pid;
        uint64_t target_addr;
        int size;
        uint8_t user_buffer[0x1000];
        struct memory_info mem_info;
        enum bp_type bt;
        enum bp_scope bs;
        int len_bytes;
        struct hwbp_info bp_info;
        int POSITION_X, POSITION_Y;
        int x, y;
    } __attribute__((packed));

public:
    void NullIo()
    {
        std::scoped_lock<SpinLock> lock(m_mutex);
        req->op = op_o;
        IoCommitAndWait();
    }

    void ExitKernel()
    {
        req->op = op_kexit;
        IoCommitAndWait();
    }
    
    int GetPid(std::string_view packageName)
    {
        DIR *dir = opendir("/proc");
        if (!dir)
            return -1;
        struct dirent *entry;

        char pathBuffer[64];
        char cmdlineBuffer[256];

        while ((entry = readdir(dir)) != nullptr)
        {
            if (entry->d_type == DT_DIR && entry->d_name[0] >= '1' && entry->d_name[0] <= '9')
            {
                snprintf(pathBuffer, sizeof(pathBuffer), "/proc/%s/cmdline", entry->d_name);
                int fd = open(pathBuffer, O_RDONLY);
                if (fd >= 0)
                {
                    ssize_t bytesRead = read(fd, cmdlineBuffer, sizeof(cmdlineBuffer) - 1);
                    close(fd);

                    if (bytesRead > 0)
                    {
                        cmdlineBuffer[bytesRead] = '\0';

                        if (packageName == std::string_view(cmdlineBuffer))
                        {
                            closedir(dir);
                            return atoi(entry->d_name);
                        }
                    }
                }
            }
        }
        closedir(dir);
        return -1;
    }
    
    int GetGlobalPid()
    {
        return global_pid;
    }
    
    void SetGlobalPid(int pid)
    {
        global_pid = pid;
    }

public:
    template <typename T>
    T Read(uint64_t address)
    {
        T value = {};
        KReadProcessMemory(address, &value, sizeof(T));
        return value;
    }

    int Read(uint64_t address, void *buffer, size_t size)
    {
        return KReadProcessMemory(address, buffer, size);
    }

    std::string ReadString(uint64_t address, size_t max_length = 128)
    {
        if (!address)
            return "";
        std::vector<char> buffer(max_length + 1, 0);
        if (Read(address, buffer.data(), max_length))
        {
            buffer[max_length] = '\0';
            return std::string(buffer.data());
        }
        return "";
    }

    std::string ReadWString(uintptr_t address, size_t length)
    {
        if (length <= 0 || length > 1024)
            return "";
        std::vector<char16_t> buffer(length);
        if (Read(address, buffer.data(), length * sizeof(char16_t)))
        {
            std::string result;
            for (size_t i = 0; i < length; ++i)
            {
                if (buffer[i] == 0)
                    break;
                result.push_back(buffer[i] < 128 ? static_cast<char>(buffer[i]) : '?');
            }
            return result;
        }
        return "";
    }

    // UTF16转UTF8: 从目标进程读取名字字符串 (最多14个UTF16字符 → 32字节UTF8)
    void GetUTF8Name(uintptr_t nameAddr, char* outBuf, size_t outBufSize = 32)
    {
        char16_t buf16[16] = { 0 };
        Read(nameAddr, buf16, 28);  // 读取28字节 = 14个UTF16字符

        char16_t* pTempUTF16 = buf16;
        char* pTempUTF8 = outBuf;
        char* pUTF8End = pTempUTF8 + outBufSize;

        while (pTempUTF16 < pTempUTF16 + 28)
        {
            if (*pTempUTF16 <= 0x007F && pTempUTF8 + 1 < pUTF8End)
            {
                *pTempUTF8++ = (char)*pTempUTF16;
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

    template <typename T>
    int Write(uint64_t address, const T &value)
    {
        return KWriteProcessMemory(address, const_cast<T *>(&value), sizeof(T));
    }

    int Write(uint64_t address, void *buffer, size_t size)
    {
        return KWriteProcessMemory(address, buffer, size);
    }

public:
    void TouchDown(int x, int y, int screenW, int screenH)
    {
        HandleTouchEvent(sm_req_op::op_down, x, y, screenW, screenH);
    }

    void TouchMove(int x, int y, int screenW, int screenH)
    {
        HandleTouchEvent(sm_req_op::op_move, x, y, screenW, screenH);
    }

    void TouchUp() { HandleTouchEvent(sm_req_op::op_up, 1, 1, 1, 1); }

public:
    int GetMemoryInformation()
    {
        return GetMemoryInfo();
    }

    const memory_info &GetMemoryInfoRef() const
    {
        return req->mem_info;
    }

    bool GetModuleAddress(std::string_view moduleName, short segmentIndex, uint64_t *outAddress, bool isStart)
    {
        if (!outAddress)
        {
            print_stderr("outAddress 为空指针\n");
            return false;
        }

        *outAddress = 0;

        if (GetMemoryInfo() != 0)
        {
            print_stderr("驱动获取内存信息失败\n");
            return false;
        }

        const auto &info = GetMemoryInfoRef();

        for (int i = 0; i < info.module_count; ++i)
        {
            const auto &mod = info.modules[i];

            std::string_view fullPath(mod.name);

            if (fullPath.length() < moduleName.length())
                continue;

            size_t pos = fullPath.length() - moduleName.length();
            if (pos > 0 && fullPath[pos - 1] != '/')
                continue;
            if (fullPath.substr(pos) != moduleName)
                continue;

            print_stderr("========== 模块信息 ==========\n");
            print_stderr("  模块索引  : %d\n", i);
            print_stderr("  模块名称  : %s\n", mod.name);
            print_stderr("  区段数量  : %d\n", mod.seg_count);
            print_stderr("  ----------------------------\n");

            for (int j = 0; j < mod.seg_count; ++j)
            {
                const auto &seg = mod.segs[j];
                print_stderr("  区段[%d]:\n", j);
                print_stderr("    index : %d\n", seg.index);
                print_stderr("    start : 0x%016llX\n", (unsigned long long)seg.start);
                print_stderr("    end   : 0x%016llX\n", (unsigned long long)seg.end);
                print_stderr("    size  : 0x%llX (%llu bytes)\n", (unsigned long long)(seg.end - seg.start), (unsigned long long)(seg.end - seg.start));
                print_stderr("    prot  : %d\n", seg.prot);
            }

            print_stderr("==============================\n");

            for (int j = 0; j < mod.seg_count; ++j)
            {
                const auto &seg = mod.segs[j];
                if (seg.index != segmentIndex)
                    continue;

                *outAddress = isStart ? seg.start : seg.end;
                return true;
            }

            print_stderr(" 模块 '%s' 中未找到区段索引 %d\n", std::string(moduleName).c_str(), segmentIndex);
            return false;
        }

        print_stderr(" 未找到模块 '%s'\n", std::string(moduleName).c_str());
        return false;
    }

    std::vector<std::pair<uintptr_t, uintptr_t>> GetScanRegions()
    {
        std::vector<std::pair<uintptr_t, uintptr_t>> regions;

        if (GetMemoryInfo() != 0)
        {
            print_stderr("驱动获取内存信息失败\n");
            return regions;
        }

        const auto &info = GetMemoryInfoRef();

        regions.reserve(info.region_count + info.module_count * 3);

        for (int i = 0; i < info.region_count; ++i)
        {
            const auto &r = info.regions[i];
            if (r.end > r.start)
                regions.emplace_back(r.start, r.end);
        }

        for (int i = 0; i < info.module_count; ++i)
        {
            const auto &mod = info.modules[i];
            for (int j = 0; j < mod.seg_count; ++j)
            {
                const auto &seg = mod.segs[j];
                regions.emplace_back(seg.start, seg.end);
            }
        }

        if (!regions.empty())
        {
            std::sort(regions.begin(), regions.end(), [](const auto &a, const auto &b)
                      { return a.first < b.first; });
        }

        return regions;
    }

public:
    const hwbp_info &GetHwbpInfoRef()
    {
        GetHwbpInfo();
        return req->bp_info;
    }
    
    hwbp_info& GetHwbpInfoModifiable() {
    GetHwbpInfo();           // 1. 从驱动读取最新数据到 req->bp_info
    return req->bp_info;     // 2. 返回可修改的引用
}

    int SetProcessHwbpRef(uint64_t target_addr, bp_type bt, bp_scope bs, int len_bytes)
    {
        return SetProcessHwbp(target_addr, bt, bs, len_bytes);
    }

    int SetProcessHwbpEmuRef(uint64_t target_addr, bp_type bt, bp_scope bs, int len_bytes)
    {
        return SetProcessHwbpEmu(target_addr, bt, bs, len_bytes);
    }

    void RemoveProcessHwbpRef()
    {
        RemoveProcessHwbp();
    }

    // 设置断点命中后修改通用寄存器值 (bit0=X0, bit1=X1, ..., bit9=X9, ..., bit29=X29, bit30=LR, bit31=SP, bit32=PC)
    void SetHwbpRegModify(int regIndex, uint64_t value)
    {
        std::scoped_lock<SpinLock> lock(m_mutex);
        req->bp_info.records[0].rw = 1;
        req->bp_info.records[0].regs[regIndex] = value;
        req->bp_info.records[0].reg_modify_mask |= (1ULL << regIndex);
    }

    // 设置断点命中后修改PC (跳过当前指令)
    void SetHwbpNewPc(uint64_t pc)
    {
        std::scoped_lock<SpinLock> lock(m_mutex);
        req->bp_info.records[0].new_pc = pc;
        req->bp_info.records[0].reg_modify_mask |= (1ULL << 32);
    }

    // 设置断点命中后修改浮点寄存器值 (bit0=V0/s0, bit1=V1/s1, ..., bit31=V31/s31)
    void SetHwbpFpModify(int regIndex, float value)
    {
        std::scoped_lock<SpinLock> lock(m_mutex);
        uint32_t bits;
        memcpy(&bits, &value, 4);
        req->bp_info.records[0].vregs[regIndex] = bits;  // 低32位=float, 高96清零
        req->bp_info.records[0].fp_modify_mask |= (1ULL << regIndex);
    }

    int HidePid(pid_t pid)
    {
        return HidePidImpl(pid);
    }


    // 一键自动扫描并隐藏所有黑名单进程（bin.mt/frida/xposed/magisk等）
    // 返回新隐藏的进程数量，<0 表示出错

    // 设置环境伪造的目标游戏进程 TGID
    // 设为 0 = 全局模式，非 0 = 仅对该进程生效（防侧信道检测）

    void RemoveHwbpRecord(int index)
    {
        if (index < 0 || index >= req->bp_info.record_count)
            return;
        const int tail_count = req->bp_info.record_count - index - 1;
        if (tail_count > 0)
            __builtin_memmove(&req->bp_info.records[index], &req->bp_info.records[index + 1], static_cast<size_t>(tail_count) * sizeof(hwbp_record));
        req->bp_info.record_count--;
        __builtin_memset(&req->bp_info.records[req->bp_info.record_count], 0, sizeof(hwbp_record));
    }

private:
    struct req_obj *req = nullptr;
    int global_pid = 0;

    inline void IoCommitAndWait()
    {
        req->kernel.store(1, std::memory_order_release);

        while (req->user.load(std::memory_order_acquire) != 1)
        {
            std::this_thread::yield();
        };

        req->user.store(0, std::memory_order_relaxed);
    }

    void InitCommunication()
    {
        prctl(PR_SET_NAME, "LS", 0, 0, 0);

        req = (req_obj *)mmap((void *)0x2025827000, sizeof(req_obj), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

        if (req == MAP_FAILED)
        {
            printf("[-] 分配共享内存失败，错误码: %d (%s)\n", errno, strerror(errno));
            return;
        }
        __builtin_memset(req, 0, sizeof(req_obj));

        printf("[+] 分配虚拟地址成功，地址: %p  大小: %lu\n", req, sizeof(req_obj));
        printf("当前进程 PID: %d\n", getpid());
        printf("等待驱动握手...\n");

        while (req->user.load(std::memory_order_acquire) != 1)
        {
        };
        req->user.store(0, std::memory_order_relaxed);

        printf("驱动已经连接\n");
    }

    void InitTouch()
    {
        req->op = op_init_touch;
        IoCommitAndWait();
    }

    // 读写
    int KReadProcessMemory(uint64_t addr, void *buffer, size_t size)
    {

        std::scoped_lock<SpinLock> lock(m_mutex);

        // 大数据自动分片，防止缓冲区溢出覆盖触摸数据
        if (size > 0x1000)
        {
            size_t processed = 0;
            while (processed < size)
            {
                size_t chunk = (size - processed > 0x1000) ? 0x1000 : (size - processed);
                req->op = op_r;
                req->pid = global_pid;
                req->target_addr = addr + processed;
                req->size = chunk;
                IoCommitAndWait();

                if (req->status <= 0)
                    return req->status;
                __builtin_memcpy((uint8_t *)buffer + processed, req->user_buffer, chunk);
                processed += chunk;
            }
            return req->status;
        }

        // 小数据快速通道
        req->op = op_r;
        req->pid = global_pid;
        req->target_addr = addr;
        req->size = size;

        IoCommitAndWait();

        // 失败时清空并返回错误码
        if (req->status <= 0)
            return req->status;

        // 极限性能且安全的内存拷贝 (防未对齐崩溃)
        switch (size)
        {
        case 1:
            __builtin_memcpy(buffer, req->user_buffer, 1);
            break;
        case 2:
            __builtin_memcpy(buffer, req->user_buffer, 2);
            break;
        case 4:
            __builtin_memcpy(buffer, req->user_buffer, 4);
            break;
        case 8:
            __builtin_memcpy(buffer, req->user_buffer, 8);
            break;
        default:
            __builtin_memcpy(buffer, req->user_buffer, size);
            break;
        }

        return req->status;
    }

    int KWriteProcessMemory(uint64_t addr, void *buffer, size_t size)
    {
        std::scoped_lock<SpinLock> lock(m_mutex);

        // 大数据自动分片，防止本地拷贝时溢出覆盖触摸数据
        if (size > 0x1000)
        {
            size_t processed = 0;
            while (processed < size)
            {
                size_t chunk = (size - processed > 0x1000) ? 0x1000 : (size - processed);
                req->op = op_w;
                req->pid = global_pid;
                req->target_addr = addr + processed;
                req->size = chunk;
                __builtin_memcpy(req->user_buffer, (uint8_t *)buffer + processed, chunk);
                IoCommitAndWait();

                if (req->status <= 0)
                    return req->status;
                processed += chunk;
            }
            return req->status;
        }

        // 小数据快速通道
        req->op = op_w;
        req->pid = global_pid;
        req->target_addr = addr;
        req->size = size;

        switch (size)
        {
        case 1:
            __builtin_memcpy(req->user_buffer, buffer, 1);
            break;
        case 2:
            __builtin_memcpy(req->user_buffer, buffer, 2);
            break;
        case 4:
            __builtin_memcpy(req->user_buffer, buffer, 4);
            break;
        case 8:
            __builtin_memcpy(req->user_buffer, buffer, 8);
            break;
        default:
            __builtin_memcpy(req->user_buffer, buffer, size);
            break;
        }

        IoCommitAndWait();

        return req->status;
    }

    int GetMemoryInfo()
    {
        std::scoped_lock<SpinLock> lock(m_mutex);
        req->op = op_m;
        req->pid = global_pid;
        IoCommitAndWait();
        return req->status;
    }

    void HandleTouchEvent(sm_req_op op, int x, int y, int screenW, int screenH)
    {
        std::scoped_lock<SpinLock> lock(m_mutex);

        if (screenW <= 0 || screenH <= 0 || req->POSITION_X <= 0 || req->POSITION_Y <= 0)
            return;

        req->op = op;

        double normX = static_cast<double>(x) / screenW;
        double normY = static_cast<double>(y) / screenH;

        if (screenW > screenH && req->POSITION_X < req->POSITION_Y)
        {
            req->x = static_cast<int>((1.0 - normY) * req->POSITION_X);
            req->y = static_cast<int>(normX * req->POSITION_Y);
        }
        else
        {
            req->x = static_cast<int>(normX * req->POSITION_X);
            req->y = static_cast<int>(normY * req->POSITION_Y);
        }

        IoCommitAndWait();
    }

    void GetHwbpInfo()
    {
        std::scoped_lock<SpinLock> lock(m_mutex);
        req->op = op_brps_weps_info;
        IoCommitAndWait();
    }

    int SetProcessHwbp(uint64_t target_addr, bp_type bt, bp_scope bs, int len_bytes = 8)
    {
        std::scoped_lock<SpinLock> lock(m_mutex);
        req->op = op_set_process_hwbp;
        req->pid = global_pid;
        req->target_addr = target_addr;
        req->bt = bt;
        req->bs = bs;
        req->len_bytes = len_bytes;
        IoCommitAndWait();
        return req->status;
    }

    int SetProcessHwbpEmu(uint64_t target_addr, bp_type bt, bp_scope bs, int len_bytes = 8)
    {
        std::scoped_lock<SpinLock> lock(m_mutex);
        req->op = op_set_process_hwbp_emu;
        req->pid = global_pid;
        req->target_addr = target_addr;
        req->bt = bt;
        req->bs = bs;
        req->len_bytes = len_bytes;
        IoCommitAndWait();
        return req->status;
    }

    void RemoveProcessHwbp()
    {
        std::scoped_lock<SpinLock> lock(m_mutex);
        req->op = op_remove_process_hwbp;
        IoCommitAndWait();
    }

    int HidePidImpl(pid_t pid)
    {
        std::scoped_lock<SpinLock> lock(m_mutex);
        req->op = op_hide_pid_add;
        req->pid = pid;
        IoCommitAndWait();
        return req->status;
    }



};

// 使用 extern 声明，在 main.cpp 中定义
extern Driver dr;

namespace SignatureScanner
{
    inline constexpr int SIG_MAX_RANGE = 1200;
    inline constexpr size_t SIG_BUFFER_SIZE = 0x8000;
    inline constexpr const char *SIG_DEFAULT_FILE = "Signature.txt";

    struct SigElement
    {
        std::vector<uint8_t> bytes;
        std::vector<bool> mask;
        bool empty() const { return bytes.empty(); }
        size_t size() const { return bytes.size(); }
        void clear()
        {
            bytes.clear();
            mask.clear();
        }
    };

    struct SigFilterResult
    {
        bool success = false;
        int changedCount = 0;
        int totalCount = 0;
        std::string oldSignature;
        std::string newSignature;
    };

    // 将所有这些函数声明为 inline
    inline std::string NormalizeSigFileName(const char *filename) {
        if (filename != nullptr && *filename != '\0')
            return std::string(filename);
        return std::string(SIG_DEFAULT_FILE);
    }

    inline bool IsAbsoluteSigPath(std::string_view path) {
        return !path.empty() && path.front() == '/';
    }

    inline std::string ResolveSigPath(std::string_view path) {
        if (IsAbsoluteSigPath(path))
            return std::string(path);
        return std::string("/data/akernel/") + std::string(path);
    }

    inline std::string FormatSignature(const SigElement &sig) {
        if (sig.empty())
            return "";
        std::string result;
        result.reserve(sig.size() * 4);
        for (size_t i = 0; i < sig.bytes.size(); ++i) {
            if (i > 0)
                result += ' ';
            if (!sig.mask[i])
                result += "??";
            else {
                char buf[8];
                snprintf(buf, sizeof(buf), "%02Xh", sig.bytes[i]);
                result += buf;
            }
        }
        return result;
    }

    inline SigElement ParseSignature(std::string_view text) {
        SigElement sig;
        if (text.empty())
            return sig;

        std::istringstream iss{std::string{text}};
        std::string token;

        while (iss >> token) {
            if (token == "??" || token == "?") {
                sig.bytes.push_back(0);
                sig.mask.push_back(false);
            } else {
                std::string hex = token;
                if (!hex.empty() && std::tolower(hex.back()) == 'h')
                    hex.pop_back();

                unsigned val = 0;
                char* endptr;
                val = strtoul(hex.c_str(), &endptr, 16);
                if (*endptr == '\0' && val <= 0xFF) {
                    sig.bytes.push_back(static_cast<uint8_t>(val));
                    sig.mask.push_back(true);
                } else {
                    print_stderr("[ParseSignature] 无法解析: '%s'\n", token.c_str());
                    sig.clear();
                    return sig;
                }
            }
        }
        return sig;
    }

    inline bool MatchSignature(const uint8_t *data, const SigElement &sig) {
        for (size_t i = 0; i < sig.size(); ++i)
            if (sig.mask[i] && data[i] != sig.bytes[i])
                return false;
        return true;
    }

    inline std::vector<uintptr_t> ScanCore(const SigElement &sig, int rangeOffset) {
        std::vector<uintptr_t> matches;
        if (sig.empty())
            return matches;

        auto regions = dr.GetScanRegions();
        if (regions.empty())
            return matches;

        const size_t sigSize = sig.size();
        std::vector<uint8_t> buffer(SIG_BUFFER_SIZE);
        const size_t step = (SIG_BUFFER_SIZE > sigSize) ? (SIG_BUFFER_SIZE - sigSize) : 1;

        for (const auto &region : regions) {
            uintptr_t rStart = region.first;
            uintptr_t rEnd = region.second;
            
            if (rEnd - rStart < sigSize)
                continue;

            for (uintptr_t addr = rStart; addr + sigSize <= rEnd; addr += step) {
                size_t readSize = std::min(static_cast<size_t>(rEnd - addr), SIG_BUFFER_SIZE);
                if (readSize < sigSize)
                    break;
                if (dr.Read(addr, buffer.data(), readSize) <= 0)
                    continue;

                size_t searchEnd = readSize - sigSize;
                for (size_t off = 0; off <= searchEnd; ++off) {
                    if (MatchSignature(buffer.data() + off, sig))
                        matches.push_back(addr + off + rangeOffset);
                }
            }
        }
        return matches;
    }

    inline bool ReadSigFile(const char *filename, int &range, std::string &sigText) {
        std::ifstream fp(filename);
        if (!fp)
            return false;

        range = 0;
        sigText.clear();
        std::string line;

        while (std::getline(fp, line)) {
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                line.pop_back();

            if (line.find("范围:") == 0) {
                auto sub = line.substr(line.find(':') + 1);
                auto it = std::find_if(sub.begin(), sub.end(), ::isdigit);
                if (it != sub.end())
                    range = atoi(&*it);
            } else if (line.find("特征码:") == 0) {
                auto sub = line.substr(line.find(':') + 1);
                auto f = sub.find_first_not_of(' ');
                if (f != std::string::npos)
                    sigText = sub.substr(f);
            }
        }
        return (range > 0 && !sigText.empty());
    }

    inline bool WriteSigFile(const char *filename, uintptr_t addr, int range, const SigElement &sig) {
        std::ofstream fp(filename);
        if (!fp)
            return false;
        fp << "目标地址: 0x" << std::hex << addr << std::dec << "\n";
        fp << "范围: " << range << "\n";
        fp << "总字节: " << sig.size() << "\n";
        fp << "特征码: " << FormatSignature(sig) << "\n";
        return !fp.fail();
    }

    inline bool ReadSigFileWithFallback(const char *filename, int &range, std::string &sigText) {
        const std::string rawName = NormalizeSigFileName(filename);
        if (ReadSigFile(rawName.c_str(), range, sigText))
            return true;
        if (!IsAbsoluteSigPath(rawName)) {
            const std::string fallback = ResolveSigPath(rawName);
            return ReadSigFile(fallback.c_str(), range, sigText);
        }
        return false;
    }

    inline bool WriteSigFileWithFallback(const char *filename, uintptr_t addr, int range, const SigElement &sig) {
        const std::string rawName = NormalizeSigFileName(filename);
        if (WriteSigFile(rawName.c_str(), addr, range, sig))
            return true;
        if (!IsAbsoluteSigPath(rawName)) {
            const std::string fallback = ResolveSigPath(rawName);
            return WriteSigFile(fallback.c_str(), addr, range, sig);
        }
        return false;
    }

    inline bool ScanAddressSignature(uintptr_t addr, int range, const char *filename = SIG_DEFAULT_FILE) {
        if (range <= 0 || range > SIG_MAX_RANGE) {
            print_stderr("[找特征] range 无效: %d (1-%d)\n", range, SIG_MAX_RANGE);
            return false;
        }
        if (addr < static_cast<uintptr_t>(range)) {
            print_stderr("[找特征] 地址过小会下溢\n");
            return false;
        }

        size_t totalSize = static_cast<size_t>(range) * 2;
        SigElement sig;
        sig.bytes.resize(totalSize);

        if (dr.Read(addr - range, sig.bytes.data(), totalSize) <= 0) {
            print_stderr("[找特征] 读取失败: 0x%llX\n", (unsigned long long)(addr - range));
            return false;
        }

        sig.mask.assign(totalSize, true);

        if (!WriteSigFileWithFallback(filename, addr, range, sig)) {
            print_stderr("[找特征] 写文件失败: %s\n", filename);
            return false;
        }

        print_stderr("[找特征] 完成 地址:0x%llX 范围:±%d 字节:%zu\n", (unsigned long long)addr, range, totalSize);
        return true;
    }

    inline SigFilterResult FilterSignature(uintptr_t addr, const char *filename = SIG_DEFAULT_FILE) {
        SigFilterResult result;

        int range = 0;
        std::string oldSigText;
        if (!ReadSigFileWithFallback(filename, range, oldSigText)) {
            print_stderr("[过滤特征] 读取文件失败: %s\n", filename);
            return result;
        }

        SigElement oldSig = ParseSignature(oldSigText);
        if (oldSig.empty()) {
            print_stderr("[过滤特征] 特征码解析失败\n");
            return result;
        }

        if (addr < static_cast<uintptr_t>(range)) {
            print_stderr("[过滤特征] 地址过小\n");
            return result;
        }

        size_t totalSize = static_cast<size_t>(range) * 2;
        std::vector<uint8_t> curData(totalSize);

        if (dr.Read(addr - range, curData.data(), totalSize) <= 0) {
            print_stderr("[过滤特征] 读取失败: 0x%llX\n", (unsigned long long)(addr - range));
            return result;
        }

        size_t cmpSize = std::min(oldSig.size(), curData.size());
        SigElement newSig;
        newSig.bytes.resize(cmpSize);
        newSig.mask.resize(cmpSize);
        result.totalCount = static_cast<int>(cmpSize);

        for (size_t i = 0; i < cmpSize; ++i) {
            if (!oldSig.mask[i]) {
                newSig.bytes[i] = 0;
                newSig.mask[i] = false;
            } else if (oldSig.bytes[i] != curData[i]) {
                newSig.bytes[i] = 0;
                newSig.mask[i] = false;
                ++result.changedCount;
            } else {
                newSig.bytes[i] = curData[i];
                newSig.mask[i] = true;
            }
        }

        result.oldSignature = oldSigText;
        result.newSignature = FormatSignature(newSig);

        WriteSigFileWithFallback(filename, addr, range, newSig);

        result.success = true;
        print_stderr("[过滤特征] 完成 总字节:%d 变化:%d\n", result.totalCount, result.changedCount);
        return result;
    }

    inline std::vector<uintptr_t> ScanSignature(const char *pattern, int range = 0) {
        SigElement sig = ParseSignature(pattern);
        if (sig.empty()) {
            print_stderr("[扫特征码] 解析失败\n");
            return {};
        }

        print_stderr("[扫特征码] 开始 长度:%zu 偏移:%d\n", sig.size(), range);
        auto matches = ScanCore(sig, range);
        print_stderr("[扫特征码] 完成 找到 %zu 个匹配\n", matches.size());
        return matches;
    }

    inline std::vector<uintptr_t> ScanSignatureFromFile(const char *filename = SIG_DEFAULT_FILE) {
        int range = 0;
        std::string sigText;
        if (!ReadSigFileWithFallback(filename, range, sigText)) {
            print_stderr("[扫特征码] 读取文件失败: %s\n", filename);
            return {};
        }

        SigElement sig = ParseSignature(sigText);
        if (sig.empty())
            return {};

        print_stderr("[扫特征码] 开始 长度:%zu 范围偏移:%d\n", sig.size(), range);
        auto matches = ScanCore(sig, range);
        print_stderr("[扫特征码] 完成 找到 %zu 个匹配\n", matches.size());

        const std::string outPath = ResolveSigPath(NormalizeSigFileName(filename));
        std::ofstream out(outPath, std::ios::app);
        if (out) {
            out << "\n扫描结果: " << matches.size() << " 个\n";
            for (auto a : matches)
                out << "0x" << std::hex << a << std::dec << "\n";
        }

        return matches;
    }
}