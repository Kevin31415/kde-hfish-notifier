#include <iostream>
// 又是不找库的一天
#include <string>
#include <sstream>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>
#include <arpa/inet.h>

// --- 简单 JSON 解析函数（仅提取 src_ip, dst_port, event_type, timestamp）---
std::string find_json_field(const std::string& json_str, const char* field_name) {
    std::string field = "\"";
    field += field_name;
    field += "\":";
    size_t pos = json_str.find(field);
    if (pos == std::string::npos) return "N/A";

    pos += field.length();
    // 跳过空格
    while (pos < json_str.length() && (json_str[pos] == ' ' || json_str[pos] == '\t')) pos++;
    
    // 如果是字符串 "xxx"
    if (pos < json_str.length() && json_str[pos] == '"') {
        pos++;
        size_t end = json_str.find('"', pos);
        if (end == std::string::npos) return "N/A";
        return json_str.substr(pos, end - pos);
    }
    // 如果是数字
    else {
        size_t end = pos;
        while (end < json_str.length() && 
               (json_str[end] == '-' || json_str[end] == '.' || 
                (json_str[end] >= '0' && json_str[end] <= '9'))) end++;
        return json_str.substr(pos, end - pos);
    }
}

// --- 弹出 KDE 桌面通知 ---
// 简单转义，供放在双引号中的 shell 参数使用
std::string shell_escape_double_quotes(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else out += c;
    }
    return out;
}

void show_notification(const std::string& message) {
    std::string esc = shell_escape_double_quotes(message);
    std::string cmd = "kdialog --title \"侦测到攻击\" --passivepopup \"" + esc + "\" 8 &";
    system(cmd.c_str());
}

// --- 主函数：启动 TCP 服务器 ---
int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);


    

    std::cout << " ___  __        _______       ___      ___  ___      ________       ________       _____      ___   ___     " << std::endl;
    std::cout << "|\\  \\|\\  \\     |\\  ___ \\     |\\  \\    /  /||\\  \\    |\\   ___  \\    |\\_____  \\     / __  \\    |\\  \\ |\\  \\    " << std::endl;
    std::cout << "\\ \\  \\/  /|_   \\ \\   __/|    \\ \\  \\  /  / /\\ \\  \\   \\ \\  \\ \\  \\   \\|____|\\ /_   |\\/_|\\  \\   \\ \\  \\_\\  \\   " << std::endl;
    std::cout << " \\ \\   ___  \\   \\ \\  \\_|/__   \\ \\  \\/  / /  \\ \\  \\   \\ \\  \\ \\  \\        \\|\\  \\  \\|/ \\ \\  \\   \\ \\______  \\  " << std::endl;
    std::cout << "  \\ \\  \\ \\  \\   \\ \\  \\_|\\ \\   \\ \\    / /    \\ \\  \\   \\ \\  \\ \\  \\      __\\_\\  \\      \\ \\  \\   \\|_____|\\  \\ " << std::endl;
    std::cout << "   \\ \\\\__\\\\ \\__\\   \\ \\_______\\   \\ \\__/ /      \\ \\__\\   \\ \\__\\\\ \\__\\    |\\_______\\      \\ \\__\\         \\ \\__\\" << std::endl;
    std::cout << "    \\|__| \\|__|    \\|_______|    \\|__|/        \\|__|    \\|__| \\|__|    \\|_______|       \\|__|          \\|__|" << std::endl;
    std::cout << "                                                                                                            " << std::endl;
    std::cout << "                                                                                                            \n\n" << std::endl;

    std::cout << "hfish KDE 通知工具\n";
    std::cout << "开始尝试绑定端口并启动服务..." << std::endl;

    // 创建 socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "socket 创建失败: " << strerror(errno) << "\n";
        return 1;
    }

    // 设置 socket 选项：端口立即重用
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "setsockopt 失败: " << strerror(errno) << "\n";
        return 1;
    }

    address.sin_family = AF_INET;
    // 只监听 127.0.0.1
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
        std::cerr << "inet_pton 失败: " << strerror(errno) << "\n";
        return 1;
    }
    address.sin_port = htons(5222); 

    // 绑定端口
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "bind 失败，端口可能被占用，原因: " << strerror(errno) << "\n";
        return 1;
    }

    // 监听
    if (listen(server_fd, 3) < 0) {
        std::cerr << "listen 失败\n";
        return 1;
    }


    std::cout << "监听地址：http://127.0.0.1:5222/webhook/hfish\n";

    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            continue;
        }

        char buffer[8192] = {0};
        int valread = read(new_socket, buffer, sizeof(buffer) - 1);

        std::string req(buffer, valread);

        // --- 解析 HTTP 请求头，确保是 POST /webhook/hfish ***
        if (req.find("POST /webhook/hfish") == std::string::npos) {
            // 发送 404
            const char* not_found_response =
                "HTTP/1.1 404 Not Found\r\n"
                "Server: HFish-C++-Notifier\r\n"
                "Content-Length: 0\r\n"
                "\r\n";
            write(new_socket, not_found_response, strlen(not_found_response));
            close(new_socket);
            continue;
        }

        // --- 找到 body 开始位置（HTTP 头部结束后） ---
        size_t pos = req.find("\r\n\r\n");
        if (pos == std::string::npos) {
            const char* bad_request =
                "HTTP/1.1 400 Bad Request\r\n"
                "Server: HFish-C++-Notifier\r\n"
                "Content-Length: 0\r\n"
                "\r\n";
            write(new_socket, bad_request, strlen(bad_request));
            close(new_socket);
            continue;
        }

        // body 就是 \r\n\r\n 之后的内容
        std::string json_body = req.substr(pos + 4);

        // --- 解析字段（参照文档） ---
        // 骄傲的使用大力出奇迹法 <_<
        std::string client = find_json_field(json_body, "client");
        std::string client_ip = find_json_field(json_body, "client_ip");
        std::string attack_type = find_json_field(json_body, "attack_type");
        std::string scan_type = find_json_field(json_body, "scan_type");
        std::string scan_port = find_json_field(json_body, "scan_port");
        std::string honeypot_type = find_json_field(json_body, "type");
        std::string honey_class = find_json_field(json_body, "class");
        std::string account = find_json_field(json_body, "account");
        std::string src_ip = find_json_field(json_body, "src_ip");
        std::string labels = find_json_field(json_body, "labels");
        std::string dst_ip = find_json_field(json_body, "dst_ip");
        std::string geo = find_json_field(json_body, "geo");
        std::string time_field = find_json_field(json_body, "time");
        std::string threat_name = find_json_field(json_body, "threat_name");
        std::string hack = "这是一行恶意代码,快去提issuse ^_^";
        std::string threat_level = find_json_field(json_body, "threat_level");
        std::string info = find_json_field(json_body, "info");

        // 构建简短通知内容（仅显示概要，避免弹窗显示不全）
        std::string msg = "HFish 检测到网络攻击 — ";
        if (attack_type != "N/A") msg += attack_type; else msg += "未知事件";
        if (src_ip != "N/A") msg += " 来自 " + src_ip;
        if (dst_ip != "N/A") msg += " -> " + dst_ip;
        if (time_field != "N/A") msg += "  时间:" + time_field;
        if (threat_level != "N/A") msg += "  等级:" + threat_level;

        // 打印日志
        std::cout << "收到告警：\n" << msg << "\n\n";

        // 弹出 KDE 通知
        show_notification(msg);

        // --- 返回 HTTP 200 响应 ---
        std::string body = "{\"status\":\"success\"}";
        std::ostringstream resp;
        resp << "HTTP/1.1 200 OK\r\n"
             << "Server: HFish-C++-Notifier\r\n"
             << "Content-Type: application/json\r\n"
             << "Content-Length: " << body.size() << "\r\n"
             << "\r\n"
             << body;

        std::string success_response = resp.str();
        write(new_socket, success_response.c_str(), success_response.size());
        close(new_socket);
    }

    return 0;
}