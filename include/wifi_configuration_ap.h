#ifndef _WIFI_CONFIGURATION_AP_H_
#define _WIFI_CONFIGURATION_AP_H_

#include <string>
#include <functional>
#include <esp_http_server.h>
#include <esp_event.h>
#include <esp_timer.h>
#include "dns_server.h"
#include <esp_netif.h>
struct WifiConfigData {
    std::string ssid;
    std::string password;
    std::string uid;
    uint8_t flag;
    uint16_t cmd;
};

class WifiConfigurationAp {
public:
    // 定义回调函数类型
    using WifiConnectSuccessCallback = std::function<void(const std::string& ssid, const std::string& password, const std::string& uid)>;
    using WifiConnectFailCallback = std::function<void(const std::string& ssid, const std::string& password, const std::string& uid)>;
    using ApConnectCallback = std::function<void(const uint8_t* mac, uint8_t aid)>;  // MAC地址和AID
    using ApDisconnectCallback = std::function<void(const uint8_t* mac, uint8_t aid)>;  // MAC地址和AID

    static WifiConfigurationAp& GetInstance();

    void SetLanguage(const std::string&& language);
    void SetSsidPrefix(const std::string&& ssid_prefix);
    void SetRedirectEnabled(bool enabled);  // 新增方法
    void Start();
    void Start(WifiConnectSuccessCallback success_cb, WifiConnectFailCallback fail_cb);
    void Stop();
    void StartWebServer();
    void StartSmartConfig();
    std::string GetWebServerUrl();
    void SetApCallbacks(ApConnectCallback connect_cb, ApDisconnectCallback disconnect_cb);  // 新增方法

private:
    void StartUdpServer();
    void UdpServerTask(void* arg);
    static void UdpServerTaskWrapper(void* arg);
    int tcp_server_socket_ = -1;
    TaskHandle_t tcp_server_task_ = nullptr; 
    WifiConfigurationAp();
    ~WifiConfigurationAp();

    // 禁用拷贝构造和赋值操作
    bool ParseWifiConfig(const uint8_t* data, size_t len, WifiConfigData& config);
    WifiConfigurationAp(const WifiConfigurationAp&) = delete;
    WifiConfigurationAp& operator=(const WifiConfigurationAp&) = delete;

    void SetConnectCallbacks(WifiConnectSuccessCallback success_cb, WifiConnectFailCallback fail_cb);
    void StartAccessPoint();
    std::string GetSsid();
    bool ConnectToWifi(const std::string& ssid, const std::string& password);
    void Save(const std::string& ssid, const std::string& password);

    static void WifiEventHandler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data);
    static void IpEventHandler(void* arg, esp_event_base_t event_base,
                             int32_t event_id, void* event_data);
    static void SmartConfigEventHandler(void* arg, esp_event_base_t event_base,
                                      int32_t event_id, void* event_data);

    std::string language_;
    std::string ssid_prefix_;
    std::string current_uid_;  // 存储当前连接尝试的 UID
    bool is_connecting_ = false;
    bool redirect_enabled_ = true;  // 新增成员变量，默认启用重定向

    esp_netif_t* ap_netif_ = nullptr;
    httpd_handle_t server_ = nullptr;
    EventGroupHandle_t event_group_ = nullptr;
    esp_timer_handle_t scan_timer_ = nullptr;
    esp_event_handler_instance_t instance_any_id_ = nullptr;
    esp_event_handler_instance_t instance_got_ip_ = nullptr;
    esp_event_handler_instance_t sc_event_instance_ = nullptr;
    DnsServer dns_server_;

    // 回调函数
    WifiConnectSuccessCallback success_callback_;
    WifiConnectFailCallback fail_callback_;
    ApConnectCallback ap_connect_callback_;  // 新增成员变量
    ApDisconnectCallback ap_disconnect_callback_;  // 新增成员变量
}; 

#endif // _WIFI_CONFIGURATION_AP_H_