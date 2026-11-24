#ifndef DRAW_CONFIG_H
#define DRAW_CONFIG_H

#include <string>
#include <fstream>
#include <cstring>
#include <cstdlib>

// 声明外部变量
extern bool find_process;
extern bool 全屏断点;
extern bool 获取数组;
extern bool 开启绘制;
extern bool 开启绘制位置;
extern bool 开启绘制受击框;
extern bool 开启绘制攻击框;
extern float slider_value;
extern float 技能位置x;
extern float 技能位置y;
extern bool 绘制2d;

// 顶技能相关变量
extern bool 顶技能;
extern float 顶技能触摸X;
extern float 顶技能触摸Y;
extern float 顶技能触摸半径;
extern bool 顶技能显示触摸点;
extern bool 顶技能启用触发区域检测;
extern float 顶技能触发X;
extern float 顶技能触发Y;
extern float 顶技能触发半径;
extern bool 顶技能显示触发区域;

// 其他变量
extern int style_idx;
extern bool permeate_record;

class DrawConfig {
private:
    // 保存单个bool到流
    static void SaveBool(std::ofstream& file, const char* name, bool value) {
        file << name << "=" << (value ? "1" : "0") << "\n";
    }
    
    // 从字符串读取bool
    static bool GetBoolFromString(const char* str) {
        return strcmp(str, "1") == 0 || strcmp(str, "true") == 0;
    }
    
    // 根据名称设置值
    static void SetValueByName(const char* name, const char* value) {
        // 进程控制
        if (strcmp(name, "find_process") == 0) find_process = GetBoolFromString(value);
        else if (strcmp(name, "全屏断点") == 0) 全屏断点 = GetBoolFromString(value);
        else if (strcmp(name, "获取数组") == 0) 获取数组 = GetBoolFromString(value);
        // 绘制开关
        else if (strcmp(name, "开启绘制") == 0) 开启绘制 = GetBoolFromString(value);
        else if (strcmp(name, "开启绘制位置") == 0) 开启绘制位置 = GetBoolFromString(value);
        else if (strcmp(name, "开启绘制受击框") == 0) 开启绘制受击框 = GetBoolFromString(value);
        else if (strcmp(name, "开启绘制攻击框") == 0) 开启绘制攻击框 = GetBoolFromString(value);
        
        // 顶技能开关
        else if (strcmp(name, "顶技能") == 0) 顶技能 = GetBoolFromString(value);
        else if (strcmp(name, "顶技能显示触摸点") == 0) 顶技能显示触摸点 = GetBoolFromString(value);
        else if (strcmp(name, "顶技能启用触发区域检测") == 0) 顶技能启用触发区域检测 = GetBoolFromString(value);
        else if (strcmp(name, "顶技能显示触发区域") == 0) 顶技能显示触发区域 = GetBoolFromString(value);
        
        // 其他开关
        else if (strcmp(name, "permeate_record") == 0) permeate_record = GetBoolFromString(value);
        else if (strcmp(name, "绘制2d") == 0) 绘制2d = GetBoolFromString(value);
        
        // 浮点数和整数
        else if (strcmp(name, "slider_value") == 0) slider_value = std::stof(value);
        else if (strcmp(name, "技能位置x") == 0) 技能位置x = std::stof(value);
        else if (strcmp(name, "技能位置y") == 0) 技能位置y = std::stof(value);
        
        else if (strcmp(name, "顶技能触摸X") == 0) 顶技能触摸X = std::stof(value);
        else if (strcmp(name, "顶技能触摸Y") == 0) 顶技能触摸Y = std::stof(value);
        else if (strcmp(name, "顶技能触摸半径") == 0) 顶技能触摸半径 = std::stof(value);
        
        else if (strcmp(name, "顶技能触发X") == 0) 顶技能触发X = std::stof(value);
        else if (strcmp(name, "顶技能触发Y") == 0) 顶技能触发Y = std::stof(value);
        else if (strcmp(name, "顶技能触发半径") == 0) 顶技能触发半径 = std::stof(value);
        
        else if (strcmp(name, "style_idx") == 0) style_idx = std::stoi(value);
    }
    
public:
    // 保存所有配置
    static bool SaveAll() {
        std::ofstream file("/data/draw_config.txt");
        if (!file.is_open()) return false;
        
        // 进程控制
        SaveBool(file, "find_process", find_process);
        SaveBool(file, "全屏断点", 全屏断点);
        SaveBool(file, "获取数组", 获取数组);
        // 绘制开关
        SaveBool(file, "开启绘制", 开启绘制);
        SaveBool(file, "开启绘制位置", 开启绘制位置);
        SaveBool(file, "开启绘制受击框", 开启绘制受击框);
        SaveBool(file, "开启绘制攻击框", 开启绘制攻击框);
        
        // 顶技能开关
        SaveBool(file, "顶技能", 顶技能);
        SaveBool(file, "顶技能显示触摸点", 顶技能显示触摸点);
        SaveBool(file, "顶技能启用触发区域检测", 顶技能启用触发区域检测);
        SaveBool(file, "顶技能显示触发区域", 顶技能显示触发区域);
        
        // 其他开关
        SaveBool(file, "permeate_record", permeate_record);
        SaveBool(file, "绘制2d", 绘制2d);
        
        // 浮点数和整数
        file << "slider_value=" << slider_value << "\n";
        file << "技能位置x=" << 技能位置x << "\n";
        file << "技能位置y=" << 技能位置y << "\n";
        
        file << "顶技能触摸X=" << 顶技能触摸X << "\n";
        file << "顶技能触摸Y=" << 顶技能触摸Y << "\n";
        file << "顶技能触摸半径=" << 顶技能触摸半径 << "\n";
        
        file << "顶技能触发X=" << 顶技能触发X << "\n";
        file << "顶技能触发Y=" << 顶技能触发Y << "\n";
        file << "顶技能触发半径=" << 顶技能触发半径 << "\n";
        
        file << "style_idx=" << style_idx << "\n";
        
        file.close();
        return true;
    }
    
    // 加载所有配置
    static bool LoadAll() {
        std::ifstream file("/data/draw_config.txt");
        if (!file.is_open()) return false;
        
        std::string line;
        while (std::getline(file, line)) {
            size_t pos = line.find('=');
            if (pos == std::string::npos) continue;
            
            std::string name = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            
            SetValueByName(name.c_str(), value.c_str());
        }
        
        file.close();
        return true;
    }
};

#endif // DRAW_CONFIG_H