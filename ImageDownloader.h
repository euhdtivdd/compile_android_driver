// ImageDownloader.h
#ifndef IMAGE_DOWNLOADER_H
#define IMAGE_DOWNLOADER_H

#include <string>
#include <vector>
#include <memory>
#include <curl/curl.h>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <fstream>
#include <map>
#include <set>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>


// 前向声明 AndroidImgui 类
class AndroidImgui;

// 声明外部变量
extern std::unique_ptr<AndroidImgui> graphics;

// 检查文件是否存在
inline bool FileExists(const std::string& path) {
    std::ifstream file(path.c_str());
    return file.good();
}

// 从文件加载纹理
inline TextureInfo LoadTextureFromFile(const std::string& filepath) {
    TextureInfo texture_info = {0, 0, 0};
    
    if (!FileExists(filepath)) {
        return texture_info;
    }
    
    // 获取文件大小
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    if (size <= 0) {
        printf("图片文件大小为0: %s\n", filepath.c_str());
        return texture_info;
    }
    
    // 读取文件内容
    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        printf("读取图片文件失败: %s\n", filepath.c_str());
        return texture_info;
    }
    
    // 使用graphics对象加载纹理
    if (graphics) {
        return graphics->LoadTextureFromMemory(buffer.data(), static_cast<int>(size));
    }
    
    return texture_info;
}

// 回调函数类型定义
using DownloadCallback = std::function<void(const std::vector<unsigned char>&, const std::string&)>;

class ImageDownloader {
private:
    CURL* curl_handle;
    std::string user_agent;
    std::string referer;
    std::mutex download_mutex;
    std::atomic<bool> is_downloading{false};
    
    // 写入数据的回调函数
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t realsize = size * nmemb;
        auto* buffer = static_cast<std::vector<unsigned char>*>(userp);
        
        try {
            size_t old_size = buffer->size();
            buffer->resize(old_size + realsize);
            memcpy(buffer->data() + old_size, contents, realsize);
        } catch (...) {
            return 0;
        }
        
        return realsize;
    }
    
    // 进度回调函数
    static int ProgressCallback(void* clientp, double dltotal, double dlnow, double ultotal, double ulnow) {
        return 0;
    }

public:
    ImageDownloader() : curl_handle(nullptr) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        
        curl_handle = curl_easy_init();
        if (curl_handle) {
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
            referer = "https://game.gtimg.cn/";
            
            curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, user_agent.c_str());
            curl_easy_setopt(curl_handle, CURLOPT_REFERER, referer.c_str());
            curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl_handle, CURLOPT_MAXREDIRS, 5L);
            curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 10L);
            curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 30L);
            curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 0L);
            curl_easy_setopt(curl_handle, CURLOPT_PROGRESSFUNCTION, ProgressCallback);
        }
    }
    
    ~ImageDownloader() {
        if (curl_handle) {
            curl_easy_cleanup(curl_handle);
        }
        curl_global_cleanup();
    }
    
    // 同步下载图片
    bool DownloadImageSync(const std::string& url, std::vector<unsigned char>& buffer) {
        std::lock_guard<std::mutex> lock(download_mutex);
        
        if (!curl_handle) {
            return false;
        }
        
        buffer.clear();
        
        curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &buffer);
        
        CURLcode res = curl_easy_perform(curl_handle);
        
        if (res != CURLE_OK) {
            printf("下载失败: %s\n", curl_easy_strerror(res));
            return false;
        }
        
        long http_code = 0;
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
        
        if (http_code != 200) {
            printf("HTTP错误: %ld\n", http_code);
            return false;
        }
        
        return !buffer.empty();
    }
    
    // 异步下载图片
    void DownloadImageAsync(const std::string& url, DownloadCallback callback) {
        if (is_downloading.load()) {
            return;
        }
        
        is_downloading.store(true);
        
        std::thread([this, url, callback]() {
            std::vector<unsigned char> buffer;
            bool success = DownloadImageSync(url, buffer);
            
            if (success && !buffer.empty()) {
                callback(buffer, url);
            }
            
            is_downloading.store(false);
        }).detach();
    }
    
    // 从URL提取文件名
    static std::string GetFileNameFromUrl(const std::string& url) {
        size_t last_slash = url.find_last_of('/');
        if (last_slash != std::string::npos) {
            std::string filename = url.substr(last_slash + 1);
            
            size_t question_mark = filename.find('?');
            if (question_mark != std::string::npos) {
                filename = filename.substr(0, question_mark);
            }
            
            return filename;
        }
        return "unknown.png";
    }
    
    // 保存图片到文件
    static bool SaveImageToFile(const std::vector<unsigned char>& data, const std::string& filename) {
        if (data.empty()) {
            return false;
        }
        
        std::string save_path = "/data/图片调用/" + filename;
        
        // 确保目录存在
        std::string dir_path = "/data/图片调用";
        struct stat info;
        if (stat(dir_path.c_str(), &info) != 0) {
            mkdir(dir_path.c_str(), 0755);
        }
        
        FILE* file = fopen(save_path.c_str(), "wb");
        if (!file) {
            printf("无法创建文件: %s\n", save_path.c_str());
            return false;
        }
        
        size_t written = fwrite(data.data(), 1, data.size(), file);
        fclose(file);
        
        return (written == data.size());
    }
    
    // 单例模式
    static ImageDownloader& GetInstance() {
        static ImageDownloader instance;
        return instance;
    }
};

// 火影忍者技能图片下载工具
class NarutoSkillImageManager {
public:
    ImageDownloader downloader;
    
private:
    std::string base_url = "https://game.gtimg.cn/images/hyrz/act/a20221108gjx/ninja/";
    
public:
    NarutoSkillImageManager() = default;
    
    // 获取指定忍者ID的技能图片URL
    std::string GetSkillImageUrl(int ninja_id, const std::string& skill_type = "jn11") {
        char url[256];
        snprintf(url, sizeof(url), "%s%05d/%s.png", 
                base_url.c_str(), ninja_id, skill_type.c_str());
        return url;
    }
    
    // 异步下载并加载纹理
    void DownloadAndLoadTextureAsync(int ninja_id, 
                                    const std::string& skill_type,
                                    std::function<void(TextureInfo)> callback) {
        std::string url = GetSkillImageUrl(ninja_id, skill_type);
        
        downloader.DownloadImageAsync(url, [callback, skill_type](const std::vector<unsigned char>& data, const std::string& url) {
            if (!data.empty() && graphics) {
                void* image_data = const_cast<unsigned char*>(data.data());
                TextureInfo texture = graphics->LoadTextureFromMemory(image_data, static_cast<int>(data.size()));
                if (texture.DS != 0) {
                    printf("成功加载网络图片纹理: %s (大小: %zu bytes)\n", 
                          skill_type.c_str(), data.size());
                    
                    if (callback) {
                        callback(texture);
                    }
                    
                    std::string filename = ImageDownloader::GetFileNameFromUrl(url);
                    ImageDownloader::SaveImageToFile(data, filename);
                }
            }
        });
    }
    
    // 检查本地是否有图片，如果没有则从网络下载
    TextureInfo GetOrDownloadSkillImage(int ninja_id, const std::string& skill_type = "jn11") {
        std::string url = GetSkillImageUrl(ninja_id, skill_type);
        std::string filename = ImageDownloader::GetFileNameFromUrl(url);
        std::string local_path = "/data/图片调用/" + filename;
        
        // 首先尝试从本地加载
        if (FileExists(local_path)) {
            printf("从本地加载图片: %s\n", local_path.c_str());
            return LoadTextureFromFile(local_path);
        }
        
        // 本地没有则从网络下载
        printf("本地不存在，从网络下载: %s\n", url.c_str());
        std::vector<unsigned char> buffer;
        if (downloader.DownloadImageSync(url, buffer)) {
            if (ImageDownloader::SaveImageToFile(buffer, filename)) {
                return LoadTextureFromFile(local_path);
            }
        }
        
        return TextureInfo{0, 0, 0};
    }
    
    // 直接从内存加载纹理
    TextureInfo LoadTextureFromMemoryData(int ninja_id, const std::string& skill_type = "jn11") {
        std::string url = GetSkillImageUrl(ninja_id, skill_type);
        std::vector<unsigned char> buffer;
        
        if (downloader.DownloadImageSync(url, buffer) && !buffer.empty() && graphics) {
            void* image_data = const_cast<unsigned char*>(buffer.data());
            return graphics->LoadTextureFromMemory(image_data, static_cast<int>(buffer.size()));
        }
        
        return TextureInfo{0, 0, 0};
    }
};

// 声明下载中的忍者集合（移到cpp文件中定义）
extern std::set<int> downloading_ninjas;

#endif // IMAGE_DOWNLOADER_H