#include "wifi_configuration_ap.h"
#include <cstdio>
#include <memory>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <esp_err.h>
#include <esp_event.h>
#include <esp_wifi.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_netif.h>
#include <lwip/ip_addr.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <cJSON.h>
#include <esp_smartconfig.h>
#include <esp_http_server.h>
#include <esp_timer.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include "ssid_manager.h"
#include "dns_server.h"

#define TAG "WifiConfigurationAp"

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

extern const char index_html_start[] asm("_binary_wifi_configuration_html_start");
extern const char done_html_start[] asm("_binary_wifi_configuration_done_html_start");

using WifiConnectSuccessCallback = WifiConfigurationAp::WifiConnectSuccessCallback;
using WifiConnectFailCallback = WifiConfigurationAp::WifiConnectFailCallback;
using ApConnectCallback = WifiConfigurationAp::ApConnectCallback;
using ApDisconnectCallback = WifiConfigurationAp::ApDisconnectCallback;

WifiConfigurationAp& WifiConfigurationAp::GetInstance() {
    static WifiConfigurationAp instance;
    return instance;
}

WifiConfigurationAp::WifiConfigurationAp()
{
    event_group_ = xEventGroupCreate();
    language_ = "zh-CN";
    // 初始化回调为空函数
    success_callback_ = [](const std::string&, const std::string&, const std::string&) {};
}

WifiConfigurationAp::~WifiConfigurationAp()
{
    if (scan_timer_) {
        esp_timer_stop(scan_timer_);
        esp_timer_delete(scan_timer_);
    }
    if (event_group_) {
        vEventGroupDelete(event_group_);
    }
    // Unregister event handlers if they were registered
    if (instance_any_id_) {
        esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id_);
    }
    if (instance_got_ip_) {
        esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip_);
    }
}

void WifiConfigurationAp::SetLanguage(const std::string &&language)
{
    language_ = language;
}

void WifiConfigurationAp::SetSsidPrefix(const std::string &&ssid_prefix)
{
    ssid_prefix_ = ssid_prefix;
}

void WifiConfigurationAp::SetRedirectEnabled(bool enabled)
{
    redirect_enabled_ = enabled;
}

void WifiConfigurationAp::Start(
    WifiConnectSuccessCallback success_cb,
    WifiConnectFailCallback fail_cb)
{
    // 设置回调函数
    SetConnectCallbacks(success_cb, fail_cb);
    
    // Register event handlers
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &WifiConfigurationAp::WifiEventHandler,
                                                        this,
                                                        &instance_any_id_));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &WifiConfigurationAp::IpEventHandler,
                                                        this,
                                                        &instance_got_ip_));

    StartAccessPoint();
    // 由外部应用决定是否启动web server
    // StartWebServer();
    StartUdpServer();
    
    // Start scan immediately
    esp_wifi_scan_start(nullptr, false);
    // Setup periodic WiFi scan timer
    esp_timer_create_args_t timer_args = {
        .callback = [](void* arg) {
            auto* self = static_cast<WifiConfigurationAp*>(arg);
            if (!self->is_connecting_) {
                esp_wifi_scan_start(nullptr, false);
            }
        },
        .arg = this,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "wifi_scan_timer",
        .skip_unhandled_events = true
    };
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &scan_timer_));
    // Start scanning every 10 seconds
    ESP_ERROR_CHECK(esp_timer_start_periodic(scan_timer_, 10000000));
}

void WifiConfigurationAp::Start()
{
    Start(nullptr, nullptr);
}

std::string WifiConfigurationAp::GetSsid()
{
    // Get MAC and use it to generate a unique SSID
    uint8_t mac[6];
    ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP));
    char ssid[32];
    snprintf(ssid, sizeof(ssid), "%s-%02X%02X", ssid_prefix_.c_str(), mac[4], mac[5]);
    return std::string(ssid);
}

std::string WifiConfigurationAp::GetWebServerUrl()
{
    // http://10.10.100.254
    return "http://10.10.100.254";
}

void WifiConfigurationAp::StartAccessPoint()
{
    // Get the SSID
    std::string ssid = GetSsid();

    // Initialize the TCP/IP stack
    ESP_ERROR_CHECK(esp_netif_init());

    // Create the default event loop
    ap_netif_ = esp_netif_create_default_wifi_ap();

    // Set the router IP address to 10.10.100.254
    esp_netif_ip_info_t ip_info;
    IP4_ADDR(&ip_info.ip, 10, 10, 100, 254);
    IP4_ADDR(&ip_info.gw, 10, 10, 100, 254);
    IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);
    esp_netif_dhcps_stop(ap_netif_);
    esp_netif_set_ip_info(ap_netif_, &ip_info);
    esp_netif_dhcps_start(ap_netif_);
    // Start the DNS server
    dns_server_.Start(ip_info.gw);

    // Initialize the WiFi stack in Access Point mode
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Set the WiFi configuration
    wifi_config_t wifi_config = {};
    strcpy((char *)wifi_config.ap.ssid, ssid.c_str());
    wifi_config.ap.ssid_len = ssid.length();
    wifi_config.ap.max_connection = 4;
    wifi_config.ap.authmode = WIFI_AUTH_OPEN;

    // Start the WiFi Access Point
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_start());

#ifdef CONFIG_SOC_WIFI_SUPPORT_5G
    // Temporarily use only 2.4G Wi-Fi.
    ESP_ERROR_CHECK(esp_wifi_set_band_mode(WIFI_BAND_MODE_2G_ONLY));
#endif

    ESP_LOGI(TAG, "Access Point started with SSID %s", ssid.c_str());
}

void WifiConfigurationAp::StartWebServer()
{
    // Start the web server
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 20;
    config.uri_match_fn = httpd_uri_match_wildcard;
    ESP_ERROR_CHECK(httpd_start(&server_, &config));

    // Register the index.html file
    httpd_uri_t index_html = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = [](httpd_req_t *req) -> esp_err_t {
            httpd_resp_send(req, index_html_start, strlen(index_html_start));
            return ESP_OK;
        },
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server_, &index_html));

    // Register the /saved/list URI
    httpd_uri_t saved_list = {
        .uri = "/saved/list",
        .method = HTTP_GET,
        .handler = [](httpd_req_t *req) -> esp_err_t {
            auto ssid_list = SsidManager::GetInstance().GetSsidList();
            std::string json_str = "[";
            for (const auto& ssid : ssid_list) {
                json_str += "\"" + ssid.ssid + "\",";
            }
            if (json_str.length() > 1) {
                json_str.pop_back(); // Remove the last comma
            }
            json_str += "]";
            httpd_resp_set_type(req, "application/json");
            httpd_resp_send(req, json_str.c_str(), HTTPD_RESP_USE_STRLEN);
            return ESP_OK;
        },
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server_, &saved_list));

    // Register the /saved/set_default URI
    httpd_uri_t saved_set_default = {
        .uri = "/saved/set_default",
        .method = HTTP_GET,
        .handler = [](httpd_req_t *req) -> esp_err_t {
            std::string uri = req->uri;
            auto pos = uri.find("?index=");
            if (pos != std::string::npos) {
                int index = std::stoi(uri.substr(pos + 7));
                ESP_LOGI(TAG, "Set default item %d", index);
                SsidManager::GetInstance().SetDefaultSsid(index);
            }
            // send {}
            httpd_resp_set_type(req, "application/json");
            httpd_resp_send(req, "{}", HTTPD_RESP_USE_STRLEN);
            return ESP_OK;
        },
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server_, &saved_set_default));

    // Register the /saved/delete URI
    httpd_uri_t saved_delete = {
        .uri = "/saved/delete",
        .method = HTTP_GET,
        .handler = [](httpd_req_t *req) -> esp_err_t {
            std::string uri = req->uri;
            auto pos = uri.find("?index=");
            if (pos != std::string::npos) {
                int index = std::stoi(uri.substr(pos + 7));
                ESP_LOGI(TAG, "Delete saved list item %d", index);
                SsidManager::GetInstance().RemoveSsid(index);
            }
            // send {}
            httpd_resp_set_type(req, "application/json");
            httpd_resp_send(req, "{}", HTTPD_RESP_USE_STRLEN);
            return ESP_OK;
        },
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server_, &saved_delete));

    // Register the /scan URI
    httpd_uri_t scan = {
        .uri = "/scan",
        .method = HTTP_GET,
        .handler = [](httpd_req_t *req) -> esp_err_t {
            uint16_t ap_num = 0;
            esp_wifi_scan_get_ap_num(&ap_num);

            if (ap_num == 0) {
                ESP_LOGI(TAG, "No APs found, scanning...");
                esp_wifi_scan_start(nullptr, true);
                esp_wifi_scan_get_ap_num(&ap_num);
            }

            auto ap_records = std::make_unique<wifi_ap_record_t[]>(ap_num);
            if (!ap_records) {
                return ESP_FAIL;
            }
            esp_wifi_scan_get_ap_records(&ap_num, ap_records.get());

            // Send the scan results as JSON
            httpd_resp_set_type(req, "application/json");
            httpd_resp_sendstr_chunk(req, "[");
            for (int i = 0; i < ap_num; i++) {
                ESP_LOGI(TAG, "SSID: %s, RSSI: %d, Authmode: %d",
                    (char *)ap_records[i].ssid, ap_records[i].rssi, ap_records[i].authmode);
                char buf[128];
                snprintf(buf, sizeof(buf), "{\"ssid\":\"%s\",\"rssi\":%d,\"authmode\":%d}",
                    (char *)ap_records[i].ssid, ap_records[i].rssi, ap_records[i].authmode);
                httpd_resp_sendstr_chunk(req, buf);
                if (i < ap_num - 1) {
                    httpd_resp_sendstr_chunk(req, ",");
                }
            }
            httpd_resp_sendstr_chunk(req, "]");
            httpd_resp_sendstr_chunk(req, NULL);
            return ESP_OK;
        },
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server_, &scan));

    // Register the form submission
    httpd_uri_t form_submit = {
        .uri = "/submit",
        .method = HTTP_POST,
        .handler = [](httpd_req_t *req) -> esp_err_t {
            char *buf;
            size_t buf_len = req->content_len;
            if (buf_len > 1024) { // 限制最大请求体大小
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Payload too large");
                return ESP_FAIL;
            }

            buf = (char *)malloc(buf_len + 1);
            if (!buf) {
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to allocate memory");
                return ESP_FAIL;
            }

            int ret = httpd_req_recv(req, buf, buf_len);
            if (ret <= 0) {
                free(buf);
                if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                    httpd_resp_send_408(req);
                } else {
                    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to receive request");
                }
                return ESP_FAIL;
            }
            buf[ret] = '\0';

            // 解析 JSON 数据
            cJSON *json = cJSON_Parse(buf);
            free(buf);
            if (!json) {
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
                return ESP_FAIL;
            }

            cJSON *ssid_item = cJSON_GetObjectItemCaseSensitive(json, "ssid");
            cJSON *password_item = cJSON_GetObjectItemCaseSensitive(json, "password");
            cJSON *uid_item = cJSON_GetObjectItemCaseSensitive(json, "uid");

            if (!cJSON_IsString(ssid_item) || (ssid_item->valuestring == NULL)) {
                cJSON_Delete(json);
                httpd_resp_send(req, "{\"success\":false,\"error\":\"无效的 SSID\"}", HTTPD_RESP_USE_STRLEN);
                return ESP_OK;
            }

            std::string ssid_str = ssid_item->valuestring;
            std::string password_str = "";
            if (cJSON_IsString(password_item) && (password_item->valuestring != NULL)) {
                password_str = password_item->valuestring;
            }
            
            // 获取 UID（如果存在）
            std::string uid_str = "";
            if (cJSON_IsString(uid_item) && (uid_item->valuestring != NULL)) {
                uid_str = uid_item->valuestring;
            }

            // 获取当前对象
            auto *this_ = static_cast<WifiConfigurationAp *>(req->user_ctx);
            // 保存当前 UID
            this_->current_uid_ = uid_str;
            
            if (!this_->ConnectToWifi(ssid_str, password_str)) {
                // 连接失败，调用失败回调
                this_->fail_callback_(ssid_str, password_str, uid_str);
                cJSON_Delete(json);
                httpd_resp_send(req, "{\"success\":false,\"error\":\"无法连接到 WiFi\"}", HTTPD_RESP_USE_STRLEN);
                return ESP_OK;
            }
            // 连接成功，保存配置并调用成功回调
            // this_->Save(ssid_str, password_str);
            cJSON_Delete(json);
            // 设置成功响应
            httpd_resp_set_type(req, "application/json");
            httpd_resp_send(req, "{\"success\":true}", HTTPD_RESP_USE_STRLEN);

            this_->success_callback_(ssid_str, password_str, uid_str);
            return ESP_OK;
        },
        .user_ctx = this
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server_, &form_submit));

    // Register the done.html page
    httpd_uri_t done_html = {
        .uri = "/done.html",
        .method = HTTP_GET,
        .handler = [](httpd_req_t *req) -> esp_err_t {
            httpd_resp_send(req, done_html_start, strlen(done_html_start));
            return ESP_OK;
        },
        .user_ctx = NULL
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server_, &done_html));

    // Register the reboot endpoint
    httpd_uri_t reboot = {
        .uri = "/reboot",
        .method = HTTP_POST,
        .handler = [](httpd_req_t *req) -> esp_err_t {
            auto* this_ = static_cast<WifiConfigurationAp*>(req->user_ctx);
            
            // 设置响应头，防止浏览器缓存
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Cache-Control", "no-store");
            // 发送响应
            httpd_resp_send(req, "{\"success\":true}", HTTPD_RESP_USE_STRLEN);
            
            // 创建一个延迟重启任务
            ESP_LOGI(TAG, "Rebooting...");
            xTaskCreate([](void *ctx) {
                // 等待200ms确保HTTP响应完全发送
                vTaskDelay(pdMS_TO_TICKS(200));
                // 停止Web服务器
                auto* self = static_cast<WifiConfigurationAp*>(ctx);
                if (self->server_) {
                    httpd_stop(self->server_);
                }
                // 再等待100ms确保所有连接都已关闭
                vTaskDelay(pdMS_TO_TICKS(100));
                // 执行重启
                esp_restart();
            }, "reboot_task", 4096, this_, 5, NULL);
            
            return ESP_OK;
        },
        .user_ctx = this
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server_, &reboot));

    auto captive_portal_handler = [](httpd_req_t *req) -> esp_err_t {
        auto *this_ = static_cast<WifiConfigurationAp *>(req->user_ctx);
        std::string url = this_->GetWebServerUrl() + "/?lang=" + this_->language_;
        
        if (this_->redirect_enabled_) {
            // Set content type to prevent browser warnings
            httpd_resp_set_status(req, "302 Found");
            httpd_resp_set_hdr(req, "Location", url.c_str());
            httpd_resp_send(req, NULL, 0);
        } else {
            // 如果不启用重定向，直接返回200 OK
            httpd_resp_set_status(req, "200 OK");
            httpd_resp_set_type(req, "text/html");
            httpd_resp_send(req, "Captive portal detected", HTTPD_RESP_USE_STRLEN);
        }
        return ESP_OK;
    };

    // Register all common captive portal detection endpoints
    const char* captive_portal_urls[] = {
        "/hotspot-detect.html",    // Apple
        "/generate_204",           // Android
        "/mobile/status.php",      // Android
        "/mtuprobe",           // Android
        "/check_network_status.txt", // Windows
        "/ncsi.txt",              // Windows
        "/fwlink/",               // Microsoft
        "/connectivity-check.html", // Firefox
        "/success.txt",           // Various
        "/portal.html",           // Various
        "/library/test/success.html" // Apple
    };

    for (const auto& url : captive_portal_urls) {
        httpd_uri_t redirect_uri = {
            .uri = url,
            .method = HTTP_GET,
            .handler = captive_portal_handler,
            .user_ctx = this
        };
        ESP_ERROR_CHECK(httpd_register_uri_handler(server_, &redirect_uri));
    }

    ESP_LOGI(TAG, "Web server started");
}

bool WifiConfigurationAp::ConnectToWifi(const std::string &ssid, const std::string &password)
{
    if (ssid.empty()) {
        ESP_LOGE(TAG, "SSID cannot be empty");
        return false;
    }
    
    if (ssid.length() > 32) {  // WiFi SSID 最大长度
        ESP_LOGE(TAG, "SSID too long");
        return false;
    }
    
    is_connecting_ = true;
    esp_wifi_scan_stop();
    xEventGroupClearBits(event_group_, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);

    wifi_config_t wifi_config;
    bzero(&wifi_config, sizeof(wifi_config));
    strcpy((char *)wifi_config.sta.ssid, ssid.c_str());
    strcpy((char *)wifi_config.sta.password, password.c_str());
    wifi_config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    wifi_config.sta.failure_retry_cnt = 1;
    
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    auto ret = esp_wifi_connect();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to connect to WiFi: %d", ret);
        is_connecting_ = false;
        return false;
    }
    ESP_LOGI(TAG, "Connecting to WiFi %s", ssid.c_str());

    // Wait for the connection to complete for 5 seconds
    EventBits_t bits = xEventGroupWaitBits(event_group_, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, pdTRUE, pdFALSE, pdMS_TO_TICKS(10000));
    is_connecting_ = false;

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to WiFi %s", ssid.c_str());
        esp_wifi_disconnect();
        return true;
    } else {
        ESP_LOGE(TAG, "Failed to connect to WiFi %s", ssid.c_str());
        return false;
    }
}

void WifiConfigurationAp::Save(const std::string &ssid, const std::string &password)
{
    ESP_LOGI(TAG, "Save SSID %s %d", ssid.c_str(), ssid.length());
    SsidManager::GetInstance().AddSsid(ssid, password);
}

void WifiConfigurationAp::SetApCallbacks(ApConnectCallback connect_cb, ApDisconnectCallback disconnect_cb)
{
    ap_connect_callback_ = connect_cb ? connect_cb : [](const uint8_t*, uint8_t) {};
    ap_disconnect_callback_ = disconnect_cb ? disconnect_cb : [](const uint8_t*, uint8_t) {};
}

void WifiConfigurationAp::WifiEventHandler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    WifiConfigurationAp* self = static_cast<WifiConfigurationAp*>(arg);
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "Station " MACSTR " joined, AID=%d", MAC2STR(event->mac), event->aid);
        if (self->ap_connect_callback_) {
            self->ap_connect_callback_(event->mac, event->aid);
        }
    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "Station " MACSTR " left, AID=%d", MAC2STR(event->mac), event->aid);
        if (self->ap_disconnect_callback_) {
            self->ap_disconnect_callback_(event->mac, event->aid);
        }
    } else if (event_id == WIFI_EVENT_STA_CONNECTED) {
        xEventGroupSetBits(self->event_group_, WIFI_CONNECTED_BIT);
    } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupSetBits(self->event_group_, WIFI_FAIL_BIT);
    } 
}

void WifiConfigurationAp::IpEventHandler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    WifiConfigurationAp* self = static_cast<WifiConfigurationAp*>(arg);
    if (event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IP:" IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(self->event_group_, WIFI_CONNECTED_BIT);
    }
}

void WifiConfigurationAp::StartSmartConfig()
{
    // 注册SmartConfig事件处理器
    ESP_ERROR_CHECK(esp_event_handler_instance_register(SC_EVENT, ESP_EVENT_ANY_ID,
                                                        &WifiConfigurationAp::SmartConfigEventHandler, this, &sc_event_instance_));

    // 初始化SmartConfig配置
    smartconfig_start_config_t cfg = SMARTCONFIG_START_CONFIG_DEFAULT();
    // cfg.esp_touch_v2_enable_crypt = true;
    // cfg.esp_touch_v2_key = "1234567890123456"; // 设置16字节加密密钥

    // 启动SmartConfig服务
    ESP_ERROR_CHECK(esp_smartconfig_start(&cfg));
    ESP_LOGI(TAG, "SmartConfig started");
}

void WifiConfigurationAp::SmartConfigEventHandler(void *arg, esp_event_base_t event_base,
                                                  int32_t event_id, void *event_data)
{
    WifiConfigurationAp *self = static_cast<WifiConfigurationAp *>(arg);

    if (event_base == SC_EVENT){
        switch (event_id){
        case SC_EVENT_SCAN_DONE:
            ESP_LOGI(TAG, "SmartConfig scan done");
            break;
        case SC_EVENT_FOUND_CHANNEL:
            ESP_LOGI(TAG, "Found SmartConfig channel");
            break;
        case SC_EVENT_GOT_SSID_PSWD:{
            ESP_LOGI(TAG, "Got SmartConfig credentials");
            smartconfig_event_got_ssid_pswd_t *evt = (smartconfig_event_got_ssid_pswd_t *)event_data;

            char ssid[32], password[64];
            memcpy(ssid, evt->ssid, sizeof(evt->ssid));
            memcpy(password, evt->password, sizeof(evt->password));
            ESP_LOGI(TAG, "SmartConfig SSID: %s, Password: %s", ssid, password);
            // 尝试连接WiFi会失败，故不连接
            self->Save(ssid, password);
            xTaskCreate([](void *ctx){
                ESP_LOGI(TAG, "Restarting in 3 second");
                vTaskDelay(pdMS_TO_TICKS(3000));
                esp_restart();
            }, "restart_task", 4096, NULL, 5, NULL);
            break;
        }
        case SC_EVENT_SEND_ACK_DONE:
            ESP_LOGI(TAG, "SmartConfig ACK sent");
            esp_smartconfig_stop();
            break;
        }
    }
}

void WifiConfigurationAp::Stop() {
    // 停止SmartConfig服务
    if (sc_event_instance_) {
        esp_event_handler_instance_unregister(SC_EVENT, ESP_EVENT_ANY_ID, sc_event_instance_);
        sc_event_instance_ = nullptr;
    }
    esp_smartconfig_stop();

    // 停止定时器
    if (scan_timer_) {
        esp_timer_stop(scan_timer_);
        esp_timer_delete(scan_timer_);
        scan_timer_ = nullptr;
    }

    // 停止Web服务器
    if (server_) {
        httpd_stop(server_);
        server_ = nullptr;
    }

    // 停止DNS服务器
    dns_server_.Stop();

    // 释放网络接口资源
    if (ap_netif_) {
        esp_netif_destroy(ap_netif_);
        ap_netif_ = nullptr;
    }

    // 停止WiFi并重置模式
    esp_wifi_stop();
    esp_wifi_deinit();
    esp_wifi_set_mode(WIFI_MODE_NULL);

    // 注销事件处理器
    if (instance_any_id_) {
        esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id_);
        instance_any_id_ = nullptr;
    }
    if (instance_got_ip_) {
        esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip_);
        instance_got_ip_ = nullptr;
    }

    ESP_LOGI(TAG, "Wifi configuration AP stopped");
}

// 添加设置回调的方法实现
void WifiConfigurationAp::SetConnectCallbacks(
    WifiConnectSuccessCallback success_cb,
    WifiConnectFailCallback fail_cb
)
{
    success_callback_ = success_cb ? success_cb : [](const std::string&, const std::string&, const std::string&) {};
    fail_callback_ = fail_cb ? fail_cb : [](const std::string&, const std::string&, const std::string&) {};
}


void WifiConfigurationAp::StartUdpServer()
{
    ESP_LOGI(TAG, "Starting UDP server...");
    
    // Create UDP socket
    tcp_server_socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (tcp_server_socket_ < 0) {
        ESP_LOGE(TAG, "Failed to create socket, error: %d", errno);
        return;
    }
    ESP_LOGI(TAG, "UDP socket created successfully, fd: %d", tcp_server_socket_);

    // Set socket options
    int opt = 1;
    if (setsockopt(tcp_server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        ESP_LOGE(TAG, "Failed to set socket options, error: %d", errno);
        close(tcp_server_socket_);
        tcp_server_socket_ = -1;
        return;
    }
    ESP_LOGI(TAG, "Socket options set successfully");

    // Set non-blocking mode
    int flags = fcntl(tcp_server_socket_, F_GETFL, 0);
    if (flags < 0) {
        ESP_LOGE(TAG, "Failed to get socket flags, error: %d", errno);
        close(tcp_server_socket_);
        tcp_server_socket_ = -1;
        return;
    }
    if (fcntl(tcp_server_socket_, F_SETFL, flags | O_NONBLOCK) < 0) {
        ESP_LOGE(TAG, "Failed to set non-blocking mode, error: %d", errno);
        close(tcp_server_socket_);
        tcp_server_socket_ = -1;
        return;
    }
    ESP_LOGI(TAG, "Socket set to non-blocking mode");

    // Bind socket to specific IP and port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("10.10.100.254");
    server_addr.sin_port = htons(12414);

    if (bind(tcp_server_socket_, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind socket to 10.10.100.254:12414, error: %d", errno);
        close(tcp_server_socket_);
        tcp_server_socket_ = -1;
        return;
    }
    ESP_LOGI(TAG, "Socket bound successfully to 10.10.100.254:12414");

    // Create task to handle UDP messages
    BaseType_t task_created = xTaskCreate(&WifiConfigurationAp::UdpServerTaskWrapper, 
                                        "udp_server", 
                                        4096, 
                                        this, 
                                        5, 
                                        &tcp_server_task_);
    
    if (task_created != pdPASS) {
        ESP_LOGE(TAG, "Failed to create UDP server task");
        close(tcp_server_socket_);
        tcp_server_socket_ = -1;
        return;
    }
    ESP_LOGI(TAG, "UDP server task created successfully");
}

void WifiConfigurationAp::UdpServerTaskWrapper(void* arg)
{
    static_cast<WifiConfigurationAp*>(arg)->UdpServerTask(arg);
}

bool WifiConfigurationAp::ParseWifiConfig(const uint8_t* data, size_t len, WifiConfigData& config) {
    if (len < 4) {
        ESP_LOGE(TAG, "Data too short");
        return false;
    }

    // Check header [0, 0, 0, 3]
    if (data[0] != 0 || data[1] != 0 || data[2] != 0 || data[3] != 3) {
        ESP_LOGE(TAG, "Invalid protocol header");
        return false;
    }

    // Find content start position
    int content_start = 4;  // Skip header
    
    // Skip length bytes (they end with a value <= 255)
    while (content_start < len && data[content_start] > 255) {
        content_start++;
    }
    content_start++;  // Skip the last length byte
    
    if (content_start >= len) {
        ESP_LOGE(TAG, "Invalid content length");
        return false;
    }

    // Parse content
    int pos = content_start;
    
    // Parse flag (1 byte)
    config.flag = data[pos++];
    
    // Parse command (2 bytes)
    if (pos + 1 >= len) {
        ESP_LOGE(TAG, "Data too short for command");
        return false;
    }
    config.cmd = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    
    // Parse SSID
    if (pos >= len) {
        ESP_LOGE(TAG, "Data too short for SSID length");
        return false;
    }
    uint8_t ssid_len = data[pos++];
    if (pos + ssid_len > len) {
        ESP_LOGE(TAG, "Data too short for SSID");
        return false;
    }
    config.ssid = std::string((char*)&data[pos], ssid_len);
    pos += ssid_len;
    
    // Parse Password
    if (pos >= len) {
        ESP_LOGE(TAG, "Data too short for password length");
        return false;
    }
    uint8_t pwd_len = data[pos++];
    if (pos + pwd_len > len) {
        ESP_LOGE(TAG, "Data too short for password");
        return false;
    }
    config.password = std::string((char*)&data[pos], pwd_len);
    pos += pwd_len;
    
    // Parse UID
    if (pos >= len) {
        ESP_LOGE(TAG, "Data too short for UID length");
        return false;
    }
    uint8_t uid_len = data[pos++];
    if (pos + uid_len > len) {
        ESP_LOGE(TAG, "Data too short for UID");
        return false;
    }
    config.uid = std::string((char*)&data[pos], uid_len);
    
    return true;
}

void WifiConfigurationAp::UdpServerTask(void* arg)
{
    WifiConfigurationAp* self = static_cast<WifiConfigurationAp*>(arg);
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[1024];

    ESP_LOGI(TAG, "UDP server task started, waiting for messages...");

    while (1) {
        // 如果正在连接中，跳过接收消息
        if (self->is_connecting_) {
            vTaskDelay(pdMS_TO_TICKS(100));  // 等待100ms再检查
            continue;
        }

        // Receive UDP message
        int len = recvfrom(self->tcp_server_socket_, buffer, sizeof(buffer) - 1, 0,
                          (struct sockaddr *)&client_addr, &client_len);
        
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No data available, wait a bit
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            ESP_LOGE(TAG, "Error occurred during receiving: %d (errno: %d)", len, errno);
            continue;
        }

        buffer[len] = '\0';
        ESP_LOGI(TAG, "Received UDP message from %s:%d, length: %d", 
                inet_ntoa(client_addr.sin_addr), 
                ntohs(client_addr.sin_port),
                len);

        // Parse the protocol
        WifiConfigData config;
        if (ParseWifiConfig((uint8_t*)buffer, len, config)) {
            ESP_LOGI(TAG, "Parsed WiFi config:");
            ESP_LOGI(TAG, "  Flag: %d", config.flag);
            ESP_LOGI(TAG, "  Command: 0x%04X", config.cmd);
            ESP_LOGI(TAG, "  SSID: %s", config.ssid.c_str());
            ESP_LOGI(TAG, "  Password: %s", config.password.c_str());
            ESP_LOGI(TAG, "  UID: %s", config.uid.c_str());

            self->is_connecting_ = true;
            self->success_callback_(config.ssid, config.password, config.uid);
            // 发送固定格式的响应
            uint8_t response[] = {
                0x00, 0x00, 0x00, 0x03,  // 固定包头
                0x03,                    // 可变长度
                0x00,                    // Flag
                0x00, 0x02              // 命令字
            };
            
            int sent = sendto(self->tcp_server_socket_, response, sizeof(response), 0,
                            (struct sockaddr *)&client_addr, client_len);
            if (sent < 0) {
                ESP_LOGE(TAG, "Failed to send response, error: %d", errno);
            } else {
                ESP_LOGI(TAG, "Response sent successfully");
            }

            vTaskDelay(pdMS_TO_TICKS(500));
        }
    }
}