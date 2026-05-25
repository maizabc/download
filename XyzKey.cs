using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace XyanKana
{
    public partial class XyzKey
    {
        public const string DefaultApiKey = "09709f9e6aa4c5523ca32070c395e2fcee4890aeadfbdc4d78c69065396ed4d3";
    }

    public class XyanAuth
    {
        public bool Success { get; set; }
        public string Status { get; set; } = "";
        public string Message { get; set; } = "";
        public string RawJson { get; set; } = "";

        public string Type { get; set; } = "";
        public string ApiKey { get; set; } = "";

        public string LicenseKey { get; set; } = "";
        public string Username { get; set; } = "";

        public string ActivatedAtRaw { get; set; } = "";
        public string ExpiresAtRaw { get; set; } = "";

        public DateTime? ActivatedAtUtc { get; set; }
        public DateTime? ExpiresAtUtc { get; set; }

        public int DevicesUsed { get; set; }
        public int DevicesLimit { get; set; }

        public bool IsLifetime
        {
            get
            {
                return string.Equals(ExpiresAtRaw, "Lifetime", StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(ExpiresAtRaw, "Vĩnh viễn", StringComparison.OrdinalIgnoreCase) ||
                       string.IsNullOrWhiteSpace(ExpiresAtRaw) && Success && !ExpiresAtUtc.HasValue;
            }
        }

        public string ActivatedAtLocalText
        {
            get
            {
                if (!ActivatedAtUtc.HasValue)
                    return ActivatedAtRaw;

                return ActivatedAtUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
            }
        }

        public string ExpiresAtLocalText
        {
            get
            {
                if (IsLifetime)
                    return "Lifetime";

                if (!ExpiresAtUtc.HasValue)
                    return ExpiresAtRaw;

                return ExpiresAtUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
            }
        }

        public string TimeRemainingText
        {
            get
            {
                if (!Success)
                    return "Unknown";

                if (IsLifetime)
                    return "Lifetime";

                if (!ExpiresAtUtc.HasValue)
                    return "Unknown";

                var remain = ExpiresAtUtc.Value - DateTime.UtcNow;

                if (remain <= TimeSpan.Zero)
                    return "Expired";

                if (remain.TotalDays >= 1)
                    return $"{(int)remain.TotalDays} days {remain.Hours} hours {remain.Minutes} minutes";

                if (remain.TotalHours >= 1)
                    return $"{(int)remain.TotalHours} hours {remain.Minutes} minutes {remain.Seconds} seconds";

                return $"{remain.Minutes} minutes {remain.Seconds} seconds";
            }
        }
    }

    public partial class XyzKey : IDisposable
    {

        private readonly HttpClient _http;
        private readonly string _authUrl;
        private readonly string _apiKey;
        private bool _disposed;

        public XyzKey() : this(Encoding.UTF8.GetString(Convert.FromBase64String("aHR0cHM6Ly94eWFua2FuYS5pby52bi9LZXlBdXRoL2FwaS9jaGVjay9DaGVjaw==")), DefaultApiKey)
        {
        }

        public XyzKey(string authUrl, string apiKey)
        {
            _authUrl = authUrl ?? throw new ArgumentNullException(nameof(authUrl));
            _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));

            _http = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(20)
            };

            _http.DefaultRequestHeaders.Add("User-Agent", "XyanKanaApp/1.0");
            _http.DefaultRequestHeaders.Add("X-App-Bypass", "xyankana_app_secret");
        }

        public async Task<XyanAuth> license(string key)
        {
            return await license(_apiKey, key);
        }

        public async Task<XyanAuth> license(string apiKey, string key)
        {
            string hwid = GetHwid();

            var payload = new Dictionary<string, string>
            {
                ["type"] = "license",
                ["apiKey"] = apiKey,
                ["licenseKey"] = key,
                ["hwid"] = hwid
            };

            string raw = await PostJsonAsync(payload);
            return ParseResult(raw, "license");
        }

        public async Task<bool> CheckKeyAsync(string key)
        {
            var result = await license(_apiKey, key);
            return result.Success;
        }

        public async Task<bool> CheckKeyAsync(string apiKey, string key)
        {
            var result = await license(apiKey, key);
            return result.Success;
        }

        public async Task<XyanAuth> login(string username, string password)
        {
            return await login(_apiKey, username, password);
        }

        public async Task<XyanAuth> login(string apiKey, string username, string password)
        {
            string hwid = GetHwid();

            var payload = new Dictionary<string, string>
            {
                ["type"] = "user",
                ["apiKey"] = apiKey,
                ["username"] = username,
                ["password"] = password,
                ["hwid"] = hwid
            };

            string raw = await PostJsonAsync(payload);
            return ParseResult(raw, "user");
        }

        public async Task<bool> CheckUserAsync(string username, string password)
        {
            var result = await login(_apiKey, username, password);
            return result.Success;
        }

        public async Task<bool> CheckUserAsync(string apiKey, string username, string password)
        {
            var result = await login(apiKey, username, password);
            return result.Success;
        }


        public async Task<string> LoginRawLicenseAsync(string apiKey, string key, string hwid)
        {
            var payload = new Dictionary<string, string>
            {
                ["type"] = "license",
                ["apiKey"] = apiKey,
                ["licenseKey"] = key,
                ["hwid"] = hwid
            };

            return await PostJsonAsync(payload);
        }

        public async Task<string> LoginRawUserAsync(string apiKey, string username, string password, string hwid)
        {
            var payload = new Dictionary<string, string>
            {
                ["type"] = "user",
                ["apiKey"] = apiKey,
                ["username"] = username,
                ["password"] = password,
                ["hwid"] = hwid
            };

            return await PostJsonAsync(payload);
        }

        private async Task<string> PostJsonAsync(Dictionary<string, string> payload)
        {
            try
            {
                var parts = new List<string>();
                foreach (var kvp in payload)
                {
                    string escapedValue = (kvp.Value ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
                    parts.Add($"\"{kvp.Key}\":\"{escapedValue}\"");
                }
                string json = "{" + string.Join(",", parts) + "}";

                using var content = new StringContent(json, Encoding.UTF8, "application/json");
                using var response = await _http.PostAsync(_authUrl, content);

                string raw = await response.Content.ReadAsStringAsync();

                if (string.IsNullOrWhiteSpace(raw))
                {
                    return "{\"success\":false,\"status\":\"error\",\"message\":\"Empty response from server.\"}";
                }

                return raw;
            }
            catch (Exception)
            {
                return "{\"success\":false,\"status\":\"error\",\"message\":\"Connection to server failed.\"}";
            }
        }

        private XyanAuth ParseResult(string raw, string expectedType)
        {
            var result = new XyanAuth
            {
                RawJson = raw ?? ""
            };

            try
            {
                result.Status = ExtractString(raw, "status");
                result.Message = ExtractString(raw, "message");
                result.ApiKey = ExtractString(raw, "api_key");
                result.Type = ExtractString(raw, "type");

                if (!string.IsNullOrWhiteSpace(result.Status))
                {
                    result.Success = result.Status.Equals("success", StringComparison.OrdinalIgnoreCase);
                }
                else
                {
                    result.Success = ExtractBool(raw, "success");
                }

                if (expectedType == "license")
                {
                    result.LicenseKey = ExtractString(raw, "key");
                    if (string.IsNullOrEmpty(result.LicenseKey))
                        result.LicenseKey = ExtractString(raw, "licenseKey");
                }
                else if (expectedType == "user")
                {
                    result.Username = ExtractString(raw, "username");
                }

                result.ActivatedAtRaw = ExtractString(raw, "activated_at");
                if (string.IsNullOrEmpty(result.ActivatedAtRaw))
                    result.ActivatedAtRaw = ExtractString(raw, "activated_at_utc");

                result.ExpiresAtRaw = ExtractString(raw, "expires_at");
                if (string.IsNullOrEmpty(result.ExpiresAtRaw))
                    result.ExpiresAtRaw = ExtractString(raw, "expires_at_utc");

                result.ActivatedAtUtc = ParseServerDate(result.ActivatedAtRaw);
                result.ExpiresAtUtc = ParseServerDate(result.ExpiresAtRaw);

                result.DevicesUsed = ExtractInt(raw, "devices_used");
                result.DevicesLimit = ExtractInt(raw, "devices_limit");

                if (string.IsNullOrWhiteSpace(result.Message))
                    result.Message = result.Success ? "Login success." : "Request failed.";
            }
            catch (Exception)
            {
                result.Success = false;
                result.Status = "error";
                result.Message = "Invalid response from server.";
                result.RawJson = raw ?? "";
            }

            return result;
        }

        private static string ExtractString(string json, string key)
        {
            if (string.IsNullOrWhiteSpace(json)) return "";
            var match = Regex.Match(json, $@"""{key}""\s*:\s*""([^""]*)""");
            if (match.Success) return match.Groups[1].Value;
            return "";
        }

        private static bool ExtractBool(string json, string key)
        {
            if (string.IsNullOrWhiteSpace(json)) return false;
            var match = Regex.Match(json, $@"""{key}""\s*:\s*(true|false)", RegexOptions.IgnoreCase);
            if (match.Success) return match.Groups[1].Value.ToLower() == "true";
            
            var strMatch = Regex.Match(json, $@"""{key}""\s*:\s*""(true|false)""", RegexOptions.IgnoreCase);
            if (strMatch.Success) return strMatch.Groups[1].Value.ToLower() == "true";
            
            return false;
        }

        private static int ExtractInt(string json, string key)
        {
            if (string.IsNullOrWhiteSpace(json)) return 0;
            var match = Regex.Match(json, $@"""{key}""\s*:\s*(-?\d+)");
            if (match.Success && int.TryParse(match.Groups[1].Value, out int v)) return v;

            var strMatch = Regex.Match(json, $@"""{key}""\s*:\s*""(-?\d+)""");
            if (strMatch.Success && int.TryParse(strMatch.Groups[1].Value, out int v2)) return v2;

            return 0;
        }

        private static DateTime? ParseServerDate(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;

            if (value.Equals("Lifetime", StringComparison.OrdinalIgnoreCase) ||
                value.Equals("Vĩnh viễn", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            if (DateTime.TryParse(value, out var dt))
            {
                if (dt.Kind == DateTimeKind.Unspecified)
                    return DateTime.SpecifyKind(dt, DateTimeKind.Utc);

                return dt.ToUniversalTime();
            }

            return null;
        }

        public string GetHwid()
        {
            try
            {
                foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up && 
                        nic.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    {
                        string mac = nic.GetPhysicalAddress().ToString();
                        if (!string.IsNullOrWhiteSpace(mac))
                            return mac;
                    }
                }
            }
            catch
            {
            }

            return Environment.MachineName;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _http.Dispose();
            _disposed = true;
        }
    }
}
