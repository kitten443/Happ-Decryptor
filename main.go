package main

import (
    "bytes"
    "crypto/rand"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "strings"
    "time"
)

var AppName = "kittyparser"

// ==================[ СТРУКТУРЫ ИЗ PARSER (hellcat) ]==================
// Используются для идеального парсинга входящего JSON

type OutboundConfig struct {
    Tag           string         `json:"tag"`
    Protocol      string         `json:"protocol"`
    Settings      interface{}    `json:"settings"`
    StreamSetting *StreamSetting `json:"streamSettings,omitempty"`
}

type StreamSetting struct {
    Network         string         `json:"network"`
    Security        string         `json:"security"`
    TlsSettings     *TlsConfig     `json:"tlsSettings,omitempty"`
    RealitySettings *RealityConfig `json:"realitySettings,omitempty"`
    WsSettings      *WsConfig      `json:"wsSettings,omitempty"`
    XhttpSettings   *XhttpConfig   `json:"xhttpSettings,omitempty"`
    GRPCConfig      *GRPCConfig    `json:"grpcSettings,omitempty"`
}

type TlsConfig struct {
    ServerName    string   `json:"serverName"`
    AllowInsecure bool     `json:"allowInsecure"`
    Alpn          []string `json:"alpn,omitempty"`
    Fingerprint   string   `json:"fingerprint,omitempty"`
}

type RealityConfig struct {
    ServerName  string `json:"serverName"`
    PublicKey   string `json:"publicKey"`
    ShortId     string `json:"shortId"`
    Fingerprint string `json:"fingerprint"`
}

type WsConfig struct {
    Path string `json:"path"`
    Host string `json:"host,omitempty"`
}

type XhttpConfig struct {
    Mode  string     `json:"mode,omitempty"`
    Path  string     `json:"path,omitempty"`
    Host  string     `json:"host,omitempty"`
    Extra *ExtraOpts `json:"extra,omitempty"`
}

type ExtraOpts struct {
    XPaddingBytes string `json:"xPaddingBytes,omitempty"`
}

type GRPCConfig struct {
    ServiceName string `json:"serviceName,omitempty"`
    Mode        string `json:"mode,omitempty"`
}

type VnextSettings struct {
    Vnext []Vnext `json:"vnext"`
}

type Vnext struct {
    Address string `json:"address"`
    Port    int    `json:"port"`
    Users   []User `json:"users"`
}

type User struct {
    Id         string `json:"id"`
    Encryption string `json:"encryption"`
    Flow       string `json:"flow,omitempty"`
}

type VMessSettings struct {
    Vnext []VMessVnext `json:"vnext"`
}

type VMessVnext struct {
    Address string      `json:"address"`
    Port    int         `json:"port"`
    Users   []VMessUser `json:"users"`
}

type VMessUser struct {
    Id       string `json:"id"`
    AlterId  int    `json:"alterId"`
    Security string `json:"security"`
}

type ServerSettings struct {
    Servers []ServerEntry `json:"servers"`
}

type ServerEntry struct {
    Address  string `json:"address"`
    Port     int    `json:"port"`
    Method   string `json:"method,omitempty"`
    Password string `json:"password"`
}

// Обертка для чтения полного конфига (где есть outbounds и remarks)
type XrayFullConfig struct {
    Remarks   string           `json:"remarks"`
    Outbounds []OutboundConfig `json:"outbounds"`
}

// ==================[ ЛОГИКА ДЕШИФРОВКИ И ЗАПРОСА ]==================

type DecryptRequest struct {
    URL string `json:"url"`
}
type DecryptResponse struct {
    DecryptedURL string `json:"decryptedUrl"`
}

func main() {
    printKitty()

    if len(os.Args) < 2 {
        fmt.Println("Usage:", AppName, "<subscription_url> [hwid] [v2rayNG]")
        os.Exit(1)
    }

    subURL := os.Args[1]
    var hwid string
    useAlternativeUA := false

    for i := 2; i < len(os.Args); i++ {
        arg := strings.ToLower(os.Args[i])
        if arg == "happ" || arg == "v2rayng" {
            useAlternativeUA = true
        } else if hwid == "" {
            hwid = os.Args[i]
        }
    }
    if hwid == "" {
        hwid = generateRandomHWID()
    }

    fmt.Println("===", AppName, "===")
    fmt.Println("Input URL:", subURL)

    if strings.HasPrefix(subURL, "happ://crypt") {
        fmt.Println("Detected encrypted 'happ://crypt' link. Decrypting...")
        decURL, err := decryptHappURL(subURL)
        if err != nil {
            fmt.Println("Decryption error:", err)
            os.Exit(1)
        }
        fmt.Println("Decrypted URL:", decURL)
        subURL = decURL
    }

    fmt.Println("Using x-hwid:", hwid)

    client := &http.Client{Timeout: 15 * time.Second}
    req, _ := http.NewRequest("GET", subURL, nil)

    var userAgent string
    if useAlternativeUA {
        userAgent = "Happ/3.25.1 (Windows NT 10.0; Win64; x64)"
    } else {
        userAgent = "v2rayNG/6.28 (Windows NT 10.0; Win64; x64)"
    }

    req.Header.Set("User-Agent", userAgent)
    req.Header.Set("x-hwid", hwid)
    req.Header.Set("x-device-os", "Windows")
    req.Header.Set("x-ver-os", "10")
    req.Header.Set("x-device-model", "PC-Desktop")
    fmt.Println("Using User-Agent:", userAgent)
    fmt.Println()

    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("http request error:", err)
        os.Exit(1)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    raw := strings.TrimSpace(string(body))

    content := raw
    if decoded, isB64 := tryDecodeBase64(raw); isB64 {
        content = decoded
    }

    parseSubscriptionContent(content)
}

func loadEnv(filename string) error {
    data, err := os.ReadFile(filename)
    if err != nil {
        return err
    }
    for _, line := range strings.Split(string(data), "\n") {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
            os.Setenv(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
        }
    }
    return nil
}

func decryptHappURL(encryptedURL string) (string, error) {
    loadEnv(".env")
    apiKey := os.Getenv("HAPP_API_KEY")
    if apiKey == "" {
        return "", fmt.Errorf("HAPP_API_KEY not found in .env")
    }

    jsonData, _ := json.Marshal(DecryptRequest{URL: encryptedURL})
    client := &http.Client{Timeout: 15 * time.Second}
    req, _ := http.NewRequest("POST", "https://happy-decoder.cc/api/v1/decrypt", bytes.NewBuffer(jsonData))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+apiKey)

    resp, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        body, _ := io.ReadAll(resp.Body)
        return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
    }

    var decResp DecryptResponse
    json.NewDecoder(resp.Body).Decode(&decResp)
    if decResp.DecryptedURL == "" {
        return "", fmt.Errorf("empty decryptedUrl")
    }
    return decResp.DecryptedURL, nil
}

// ==================[ КОНВЕРТАЦИЯ JSON -> ССЫЛКИ ]==================

func parseSubscriptionContent(content string) {
    var extractedLinks []string

    // Пытаемся распарсить как массив полных конфигов Xray
    var configs []XrayFullConfig
    if err := json.Unmarshal([]byte(content), &configs); err == nil {
        fmt.Println("[Detected Xray JSON Configs - Converting to standard links...]")
        for _, conf := range configs {
            name := conf.Remarks
            for _, out := range conf.Outbounds {
                if out.Protocol == "freedom" || out.Protocol == "blackhole" || out.Protocol == "dns" {
                    continue
                }
                if link := convertToLink(out, name); link != "" {
                    extractedLinks = append(extractedLinks, link)
                }
            }
        }
    }

    // Если ссылки извлечены, подменяем контент для обработки вашим парсером
    if len(extractedLinks) > 0 {
        content = strings.Join(extractedLinks, "\n")
    }

    // Дальше работает ваш оригинальный красивый вывод
    lines := strings.Split(content, "\n")
    var allLinks, vlessLinks, vmessLinks, ssLinks, trojanLinks, tuicLinks, hysteriaLinks, otherLinks []string

    fmt.Println("\n[Parsed Links]")
    fmt.Println(strings.Repeat("=", 80))

    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        switch {
        case strings.HasPrefix(line, "vless://"):
            vlessLinks = append(vlessLinks, line)
            allLinks = append(allLinks, line)
            parseVlessLink(line)
        case strings.HasPrefix(line, "vmess://"):
            vmessLinks = append(vmessLinks, line)
            allLinks = append(allLinks, line)
            parseVmessLink(line)
        case strings.HasPrefix(line, "ss://"):
            ssLinks = append(ssLinks, line)
            allLinks = append(allLinks, line)
            parseSSLink(line)
        case strings.HasPrefix(line, "trojan://"):
            trojanLinks = append(trojanLinks, line)
            allLinks = append(allLinks, line)
            parseTrojanLink(line)
        case strings.HasPrefix(line, "tuic://"):
            tuicLinks = append(tuicLinks, line)
            allLinks = append(allLinks, line)
            parseTuicLink(line)
        case strings.HasPrefix(line, "hysteria://") || strings.HasPrefix(line, "hysteria2://"):
            hysteriaLinks = append(hysteriaLinks, line)
            allLinks = append(allLinks, line)
            parseHysteriaLink(line)
        default:
            otherLinks = append(otherLinks, line)
        }
    }

    fmt.Println("\n[Full Links]")
    fmt.Println(strings.Repeat("=", 80))
    for i, link := range allLinks {
        fmt.Printf("%d: %s\n", i+1, link)
    }

    fmt.Println("\n[Statistics]")
    fmt.Println(strings.Repeat("-", 80))
    total := len(vlessLinks) + len(vmessLinks) + len(ssLinks) + len(trojanLinks) + len(tuicLinks) + len(hysteriaLinks)
    fmt.Printf("Total valid links: %d\n", total)
    fmt.Printf("  VLESS: %d\n", len(vlessLinks))
    fmt.Printf("  VMESS: %d\n", len(vmessLinks))
    fmt.Printf("  Shadowsocks: %d\n", len(ssLinks))
    fmt.Printf("  Trojan: %d\n", len(trojanLinks))
    fmt.Println(strings.Repeat("=", 80))
}

// Вспомогательная функция для безопасного извлечения настроек
func getSettings[T any](raw interface{}) (T, error) {
    var zero T
    b, err := json.Marshal(raw)
    if err != nil {
        return zero, err
    }
    var result T
    err = json.Unmarshal(b, &result)
    return result, err
}

// --- Генераторы ссылок из структур ---

func convertToLink(out OutboundConfig, name string) string {
    switch out.Protocol {
    case "vless":
        return buildVlessFromStruct(out, name)
    case "vmess":
        return buildVmessFromStruct(out, name)
    case "trojan":
        return buildTrojanFromStruct(out, name)
    case "shadowsocks":
        return buildSSFromStruct(out, name)
    }
    return ""
}

func buildVlessFromStruct(out OutboundConfig, name string) string {
    settings, err := getSettings[VnextSettings](out.Settings)
    if err != nil || len(settings.Vnext) == 0 {
        return ""
    }
    vn := settings.Vnext[0]
    if len(vn.Users) == 0 {
        return ""
    }
    user := vn.Users[0]
    stream := out.StreamSetting
    if stream == nil {
        return ""
    }

    params := url.Values{}
    params.Set("type", stream.Network)
    params.Set("security", stream.Security)
    if user.Flow != "" {
        params.Set("flow", user.Flow)
    }

    if stream.Security == "reality" && stream.RealitySettings != nil {
        r := stream.RealitySettings
        params.Set("sni", r.ServerName)
        params.Set("fp", r.Fingerprint)
        params.Set("pbk", r.PublicKey)
        params.Set("sid", r.ShortId)
    } else if stream.Security == "tls" && stream.TlsSettings != nil {
        t := stream.TlsSettings
        params.Set("sni", t.ServerName)
        params.Set("fp", t.Fingerprint)
        if len(t.Alpn) > 0 {
            params.Set("alpn", strings.Join(t.Alpn, ","))
        }
    }

    if stream.Network == "ws" && stream.WsSettings != nil {
        params.Set("path", stream.WsSettings.Path)
        if stream.WsSettings.Host != "" {
            params.Set("host", stream.WsSettings.Host)
        }
    } else if stream.Network == "grpc" && stream.GRPCConfig != nil {
        params.Set("serviceName", stream.GRPCConfig.ServiceName)
        if stream.GRPCConfig.Mode != "" {
            params.Set("mode", stream.GRPCConfig.Mode)
        }
    } else if (stream.Network == "xhttp" || stream.Network == "splithttp") && stream.XhttpSettings != nil {
        x := stream.XhttpSettings
        params.Set("path", x.Path)
        if x.Host != "" {
            params.Set("host", x.Host)
        }
        if x.Mode != "" {
            params.Set("mode", x.Mode)
        }
        // Обработка дополнительных заголовков XHTTP (Extra)
        if x.Extra != nil {
            if extraJSON, err := json.Marshal(x.Extra); err == nil {
                params.Set("extra", string(extraJSON))
            }
        }
    }

    return fmt.Sprintf("vless://%s@%s:%d?%s#%s", user.Id, vn.Address, vn.Port, params.Encode(), url.QueryEscape(name))
}

func buildVmessFromStruct(out OutboundConfig, name string) string {
    settings, err := getSettings[VMessSettings](out.Settings)
    if err != nil || len(settings.Vnext) == 0 {
        return ""
    }
    vn := settings.Vnext[0]
    if len(vn.Users) == 0 {
        return ""
    }
    user := vn.Users[0]
    stream := out.StreamSetting
    if stream == nil {
        return ""
    }

    vmessObj := map[string]interface{}{
        "v":    "2",
        "ps":   name,
        "add":  vn.Address,
        "port": vn.Port,
        "id":   user.Id,
        "aid":  user.AlterId,
        "scy":  user.Security,
        "net":  stream.Network,
        "type": "none",
        "tls":  stream.Security,
    }

    if stream.TlsSettings != nil {
        vmessObj["sni"] = stream.TlsSettings.ServerName
        vmessObj["fp"] = stream.TlsSettings.Fingerprint
        if len(stream.TlsSettings.Alpn) > 0 {
            vmessObj["alpn"] = strings.Join(stream.TlsSettings.Alpn, ",")
        }
    }
    if stream.WsSettings != nil {
        vmessObj["path"] = stream.WsSettings.Path
        vmessObj["host"] = stream.WsSettings.Host
    }
    if stream.GRPCConfig != nil {
        vmessObj["path"] = stream.GRPCConfig.ServiceName
    }

    jsonData, _ := json.Marshal(vmessObj)
    return "vmess://" + base64.StdEncoding.EncodeToString(jsonData)
}

func buildTrojanFromStruct(out OutboundConfig, name string) string {
    settings, err := getSettings[ServerSettings](out.Settings)
    if err != nil || len(settings.Servers) == 0 {
        return ""
    }
    s := settings.Servers[0]
    stream := out.StreamSetting
    if stream == nil {
        return ""
    }

    params := url.Values{}
    params.Set("type", stream.Network)
    params.Set("security", stream.Security)

    if stream.TlsSettings != nil {
        params.Set("sni", stream.TlsSettings.ServerName)
        params.Set("fp", stream.TlsSettings.Fingerprint)
    }
    if stream.GRPCConfig != nil {
        params.Set("serviceName", stream.GRPCConfig.ServiceName)
    }
    if stream.WsSettings != nil {
        params.Set("path", stream.WsSettings.Path)
        params.Set("host", stream.WsSettings.Host)
    }

    return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", s.Password, s.Address, s.Port, params.Encode(), url.QueryEscape(name))
}

func buildSSFromStruct(out OutboundConfig, name string) string {
    settings, err := getSettings[ServerSettings](out.Settings)
    if err != nil || len(settings.Servers) == 0 {
        return ""
    }
    s := settings.Servers[0]
    userInfo := base64.StdEncoding.EncodeToString([]byte(s.Method + ":" + s.Password))
    return fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, s.Address, s.Port, url.QueryEscape(name))
}

// ==================[ ПАРСЕРЫ СТАНДАРТНЫХ ССЫЛОК (ДЛЯ КРАСИВОГО ВЫВОДА) ]==================

func parseVlessLink(link string) {
    u, _ := url.Parse(link)
    q := u.Query()
    fmt.Printf("[VLESS] Name: %s\n", u.Fragment)
    fmt.Printf("  Server: %s:%s\n", u.Hostname(), u.Port())
    fmt.Printf("  UUID: %s\n", u.User.Username())
    fmt.Printf("  Security: %s\n", q.Get("security"))
    fmt.Printf("  Flow: %s\n", q.Get("flow"))
    fmt.Printf("  SNI: %s\n", q.Get("sni"))
    fmt.Printf("  Type: %s\n", q.Get("type"))
    fmt.Println(strings.Repeat("-", 40))
}

func parseVmessLink(link string) {
    trimmed := strings.TrimPrefix(link, "vmess://")
    decoded, err := base64.StdEncoding.DecodeString(trimmed)
    if err != nil {
        return
    }
    var vmessData map[string]interface{}
    json.Unmarshal(decoded, &vmessData)
    fmt.Printf("[VMESS] Name: %v\n", vmessData["ps"])
    fmt.Printf("  Server: %v:%v\n", vmessData["add"], vmessData["port"])
    fmt.Printf("  UUID: %v\n", vmessData["id"])
    fmt.Printf("  Network: %v\n", vmessData["net"])
    fmt.Println(strings.Repeat("-", 40))
}

func parseSSLink(link string) {
    u, _ := url.Parse(link)
    decoded, _ := base64.StdEncoding.DecodeString(u.User.Username())
    parts := strings.SplitN(string(decoded), ":", 2)
    fmt.Printf("[SS] Name: %s\n", u.Fragment)
    fmt.Printf("  Server: %s:%s\n", u.Hostname(), u.Port())
    if len(parts) == 2 {
        fmt.Printf("  Method: %s\n", parts[0])
    }
    fmt.Println(strings.Repeat("-", 40))
}

func parseTrojanLink(link string) {
    u, _ := url.Parse(link)
    q := u.Query()
    fmt.Printf("[TROJAN] Name: %s\n", u.Fragment)
    fmt.Printf("  Server: %s:%s\n", u.Hostname(), u.Port())
    fmt.Printf("  Security: %s\n", q.Get("security"))
    fmt.Println(strings.Repeat("-", 40))
}

func parseTuicLink(link string) {
    u, _ := url.Parse(link)
    fmt.Printf("[TUIC] Name: %s\n", u.Fragment)
    fmt.Printf("  Server: %s\n", u.Host)
    fmt.Println(strings.Repeat("-", 40))
}

func parseHysteriaLink(link string) {
    u, _ := url.Parse(link)
    fmt.Printf("[HYSTERIA] Name: %s\n", u.Fragment)
    fmt.Printf("  Server: %s\n", u.Host)
    fmt.Println(strings.Repeat("-", 40))
}

// ==================[ УТИЛИТЫ ]==================

func tryDecodeBase64(s string) (string, bool) {
    s = strings.TrimSpace(s)
    if out, err := decodeWithPadding(s, base64.StdEncoding); err == nil {
        return out, true
    }
    if out, err := decodeWithPadding(s, base64.URLEncoding); err == nil {
        return out, true
    }
    return "", false
}

func decodeWithPadding(s string, enc *base64.Encoding) (string, error) {
    if m := len(s) % 4; m != 0 {
        s += strings.Repeat("=", 4-m)
    }
    b, err := enc.DecodeString(s)
    if err != nil {
        return "", err
    }
    return string(b), nil
}

func generateRandomHWID() string {
    buf := make([]byte, 16)
    rand.Read(buf)
    return "device-" + hex.EncodeToString(buf)
}

func printKitty() {
    kitty := `
    /\_/\  
   ( o.o ) 
    > ^ <
   /     \
  /       \
 /         \
/  Meow!   \`
    fmt.Println(kitty)
    fmt.Println()
}
