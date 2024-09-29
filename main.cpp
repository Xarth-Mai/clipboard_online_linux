#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstdio>
#include <openssl/evp.h>  // 新的哈希接口
#include <sstream>
#include <iomanip>
#include <csignal>

// 定义常量 PORT 和 AUTH_PASSWORD
constexpr int PORT = 8777;  // 服务器监听的端口号
const std::string AUTH_PASSWORD = "1234"; // 硬编码的密码，用于身份验证
int server_fd; // 服务器套接字

// 将数据设置到剪贴板的函数
void set_clipboard(const std::string &data) {
    // 使用 xclip 将数据添加到剪贴板，确保覆盖
    if (FILE *pipe = popen("xclip -selection clipboard -i", "w")) {
        fwrite(data.c_str(), sizeof(char), data.size(), pipe);
        pclose(pipe); // 关闭管道
    } else {
        std::cerr << "无法打开管道" << std::endl; // 错误处理
    }
}

// 从剪贴板获取数据的函数
std::string get_clipboard() {
    std::string result; // 存储剪贴板内容
    if (FILE *pipe = popen("xclip -selection clipboard -o", "r")) {
        char buffer[128];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer; // 读取剪贴板内容并追加到结果中
        }
        pclose(pipe); // 关闭管道
    } else {
        std::cerr << "无法打开管道" << std::endl; // 错误处理
    }
    return result; // 返回剪贴板内容
}

// 进行URL解码的函数
std::string url_decode(const std::string &encoded) {
    std::string decoded;
    for (std::size_t i = 0; i < encoded.length(); ++i) {
        if (encoded[i] == '%') {
            if (i + 2 < encoded.length()) {
                // 获取两位十六进制字符
                std::string hex_str = encoded.substr(i + 1, 2);
                char *end_ptr = nullptr;

                // 将十六进制字符串转换为数值

                // 检查转换是否成功
                if (const unsigned long hex_value = strtoul(hex_str.c_str(), &end_ptr, 16); *end_ptr == '\0' && hex_value <= 0xFF) {
                    decoded += static_cast<char>(hex_value);
                    i += 2;  // 跳过两个已解析的字符
                } else {
                    // 处理无效的 % 编码，保留原始值
                    decoded += '%';
                }
            } else {
                // 无效的 % 编码，保留原始值
                decoded += '%';
            }
        } else if (encoded[i] == '+') {
            decoded += ' ';  // 将 + 转换为空格
        } else {
            decoded += encoded[i];  // 保留其他字符
        }
    }
    return decoded;
}

// 计算输入字符串的 MD5 哈希值的函数
std::string md5(const std::string &input) {
    unsigned char digest[EVP_MAX_MD_SIZE]; // 存储哈希结果
    unsigned int digest_length = 0; // 哈希长度

    // 创建 MD5 哈希上下文
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr); // 初始化哈希上下文
    EVP_DigestUpdate(ctx, input.data(), input.size()); // 更新哈希上下文
    EVP_DigestFinal_ex(ctx, digest, &digest_length); // 获取哈希结果
    EVP_MD_CTX_free(ctx); // 释放上下文

    // 将哈希结果转换为十六进制字符串
    std::ostringstream oss;
    for (unsigned int i = 0; i < digest_length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }
    return oss.str(); // 返回 MD5 哈希值
}

// 进行身份验证的函数
bool authenticate(const std::string &timestamp, const std::string &md5_hash) {
    // 计算期望的哈希值
    const std::string computed_hash = md5(timestamp + AUTH_PASSWORD);
    return md5_hash == computed_hash; // 进行哈希匹配
}

// 处理客户端请求的函数
void handle_request(const int client_socket) {
    char buffer[40960]; // 存储接收的数据
    read(client_socket, buffer, sizeof(buffer) - 1); // 从客户端读取数据
    buffer[sizeof(buffer) - 1] = '\0'; // 确保以 null 结尾

    std::string request(buffer); // 将读取的数据转换为字符串
    std::string response; // 存储响应内容

    // 解析请求方法（GET 或 POST）
    const std::string method = request.substr(0, request.find(' '));
    std::string timestamp;
    std::string md5_hash;

    // 获取时间戳和 MD5 哈希值
    const size_t timestamp_pos = request.find("Timestamp: ");
    if (const size_t md5_pos = request.find("MD5: "); timestamp_pos != std::string::npos && md5_pos != std::string::npos) {
        timestamp = request.substr(timestamp_pos + 11, request.find("\r\n", timestamp_pos) - (timestamp_pos + 11));
        md5_hash = request.substr(md5_pos + 5, request.find("\r\n", md5_pos) - (md5_pos + 5));
    }

    // 进行身份验证
    if (!authenticate(timestamp, md5_hash)) {
        // 身份验证失败，返回 403 Forbidden
        response = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n403 Forbidden";
    } else {
        if (method == "GET") {
            // 身份验证成功，获取剪贴板内容并返回
            const std::string clipboard_content = get_clipboard();
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + clipboard_content;
        } else if (method == "POST") {
            // 身份验证成功，获取请求体并设置到剪贴板
            std::string body = request.substr(request.find("\r\n\r\n") + 4); // 获取请求体
            if (!body.empty()) {
                body.erase(0, 1); // 删除第一个字符
            }
            const std::string body_decode = url_decode(body);

            set_clipboard(body_decode); // 将请求体数据设置到剪贴板
            response = "HTTP/1.1 204 No Content\r\n\r\n"; // 成功但无内容返回
        } else {
            // 不支持的请求方法，返回 400 Bad Request
            response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\n400 Bad Request";
        }
    }

    // 发送响应给客户端
    write(client_socket, response.c_str(), response.size());
    close(client_socket); // 关闭与客户端的连接
}

// 信号处理函数，用于关闭套接字和退出程序
void signal_handler(const int signum) {
    std::cout << "\n接收到信号 " << signum << "，正在关闭服务器..." << std::endl;

    if (server_fd >= 0) {
        close(server_fd); // 关闭服务器套接字
        std::cout << "服务器套接字已关闭。" << std::endl;
    }

    exit(signum); // 退出程序
}

[[noreturn]] int main() {
    struct sockaddr_in server_addr{}, client_addr{};
    socklen_t addr_len = sizeof(client_addr); // 地址长度

    // 注册信号处理程序
    signal(SIGINT, signal_handler);  // 捕获 Ctrl+C (SIGINT)
    signal(SIGTERM, signal_handler); // 捕获终止信号 (SIGTERM)

    // 创建服务器套接字
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("无法创建套接字"); // 错误处理
        exit(EXIT_FAILURE);
    }

    // 初始化服务器地址结构
    memset(&server_addr, 0, sizeof(server_addr)); // 清空结构
    server_addr.sin_family = AF_INET; // IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY; // 允许连接的任何地址
    server_addr.sin_port = htons(PORT); // 设置端口号

    // 绑定套接字
    if (bind(server_fd, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        perror("绑定失败"); // 错误处理
        close(server_fd); // 关闭套接字
        exit(EXIT_FAILURE);
    }

    // 监听连接
    if (listen(server_fd, 10) < 0) {
        perror("监听失败"); // 错误处理
        close(server_fd); // 关闭套接字
        exit(EXIT_FAILURE);
    }

    std::cout << "服务器在端口 " << PORT << " 上监听..." << std::endl; // 输出服务器状态

    while (true) {
        // 接受客户端连接
        const int client_socket = accept(server_fd, reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len);
        if (client_socket < 0) {
            perror("接受连接失败"); // 错误处理
            continue; // 继续等待下一个连接
        }

        // 处理客户端请求
        handle_request(client_socket);
    }
}