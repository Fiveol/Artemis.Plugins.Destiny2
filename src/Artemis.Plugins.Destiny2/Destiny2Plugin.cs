using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

// Artemis namespaces – adjust to your actual Artemis version
using Artemis.Core;
using Artemis.Core.Modules;
using Artemis.Core.Services;

// -----------------------------
// Data model exposed to Artemis
// -----------------------------

public class Destiny2DataModel : DataModel
{
    public bool IsLoggedIn { get; set; }
    public string DisplayName { get; set; } = "Please Sign In";
    public string SubclassName { get; set; } = "Unknown Subclass";
}

// -----------------------------
// Settings for the plugin
// -----------------------------

public class Destiny2Settings
{
    public string ApiKey { get; set; } = "";          // Bungie API key
    public string ClientId { get; set; } = "48933";   // Your app's client ID
    public int PollIntervalMs { get; set; } = 5000;   // 5 seconds
}

// -----------------------------
// Token persistence model
// -----------------------------

public class Destiny2TokenStore
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }

    [JsonPropertyName("membership_id")]
    public string MembershipId { get; set; }

    [JsonPropertyName("membership_type")]
    public int MembershipType { get; set; }
}

// -----------------------------
// Bungie service – handles OAuth, manifest, polling
// -----------------------------

public class BungieService : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly Destiny2Settings _settings;
    private readonly string _tokenFilePath;
    private readonly string _cacheFilePath;

    private Destiny2TokenStore _tokens;
    private CancellationTokenSource _pollCts;

    // Events wiring into the Artemis module/data model
    public event Action<string> DisplayNameChanged;
    public event Action<string> SubclassNameChanged;
    public event Action<bool> LoggedInChanged;

    private const string AuthorizationBaseUrl = "https://www.bungie.net/en/OAuth/Authorize";
    private const string TokenUrl = "https://www.bungie.net/Platform/App/OAuth/Token/";
    private const string RedirectUri = "http://localhost:8080/callback";

    public BungieService(Destiny2Settings settings, string dataFolder)
    {
        _settings = settings;
        Directory.CreateDirectory(dataFolder);

        _tokenFilePath = Path.Combine(dataFolder, "tokens.json");
        _cacheFilePath = Path.Combine(dataFolder, "subclass_cache.json");

        _httpClient = new HttpClient();
        if (!string.IsNullOrWhiteSpace(settings.ApiKey))
            _httpClient.DefaultRequestHeaders.Add("X-API-Key", settings.ApiKey);
    }

    // -----------------------------
    // Public entry points
    // -----------------------------

    public async Task<bool> AutoLoginAndStartPollingAsync()
    {
        if (!LoadTokens())
            return false;

        if (!await ValidateTokenAsync(_tokens.AccessToken))
            return false;

        LoggedInChanged?.Invoke(true);
        StartPolling();
        return true;
    }

    public async Task<bool> StartInteractiveLoginAsync()
    {
        // OAuth: open browser, listen on localhost:8080/callback, exchange code for token
        var state = Guid.NewGuid().ToString("N");

        string authorizeUrl =
            $"{AuthorizationBaseUrl}?client_id={_settings.ClientId}&response_type=code&redirect_uri={WebUtility.UrlEncode(RedirectUri)}&state={state}";

        // Start local HTTP listener
        using var listener = new HttpListener();
        listener.Prefixes.Add("http://localhost:8080/callback/");
        listener.Start();

        // Open browser
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = authorizeUrl,
                UseShellExecute = true
            });
        }
        catch
        {
            // ignore; user can paste link manually
        }

        // Wait for callback
        var context = await listener.GetContextAsync();
        var request = context.Request;
        var response = context.Response;

        string htmlResponse = "<html><body>Authentication successful! You can close this window now.</body></html>";
        var buffer = System.Text.Encoding.UTF8.GetBytes(htmlResponse);
        response.ContentLength64 = buffer.Length;
        using (var output = response.OutputStream)
            await output.WriteAsync(buffer, 0, buffer.Length);

        var query = HttpUtility.ParseQueryString(request.Url.Query);
        string code = query["code"];
        string returnedState = query["state"];

        if (string.IsNullOrEmpty(code) || returnedState != state)
            return false;

        // Exchange code for token
        var form = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("code", code),
            new KeyValuePair<string, string>("client_id", _settings.ClientId),
            new KeyValuePair<string, string>("redirect_uri", RedirectUri)
        });

        var tokenResponse = await _httpClient.PostAsync(TokenUrl, form);
        if (!tokenResponse.IsSuccessStatusCode)
            return false;

        var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(tokenJson);
        if (!doc.RootElement.TryGetProperty("access_token", out var accessTokenElement))
            return false;

        string accessToken = accessTokenElement.GetString();

        // Get membership info
        var headers = new HttpRequestMessage(HttpMethod.Get, "https://www.bungie.net/Platform/User/GetMembershipsForCurrentUser/");
        headers.Headers.Add("Authorization", $"Bearer {accessToken}");
        var membershipResp = await _httpClient.SendAsync(headers);

        if (!membershipResp.IsSuccessStatusCode)
            return false;

        var membershipJson = await membershipResp.Content.ReadAsStringAsync();
        using var membershipDoc = JsonDocument.Parse(membershipJson);

        var memberships = membershipDoc.RootElement
            .GetProperty("Response")
            .GetProperty("destinyMemberships");

        if (memberships.GetArrayLength() == 0)
            return false;

        var firstMembership = memberships[0];
        string membershipId = firstMembership.GetProperty("membershipId").GetString();
        int membershipType = firstMembership.GetProperty("membershipType").GetInt32();

        _tokens = new Destiny2TokenStore
        {
            AccessToken = accessToken,
            MembershipId = membershipId,
            MembershipType = membershipType
        };

        SaveTokens();

        LoggedInChanged?.Invoke(true);
        StartPolling();
        return true;
    }

    public void StartPolling()
    {
        _pollCts?.Cancel();
        _pollCts = new CancellationTokenSource();
        _ = PollLoopAsync(_pollCts.Token);
    }

    public void StopPolling()
    {
        _pollCts?.Cancel();
        _pollCts = null;
    }

    // -----------------------------
    // Poll loop: gets display name + subclass
    // -----------------------------

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (_tokens == null)
                    return;

                // 1) Display name
                var name = await GetDisplayNameAsync(_tokens.AccessToken);
                if (!string.IsNullOrEmpty(name))
                    DisplayNameChanged?.Invoke(name);

                // 2) Subclass
                var subclassName = await GetEquippedSubclassNameAsync(
                    _tokens.AccessToken,
                    _tokens.MembershipId,
                    _tokens.MembershipType);

                if (!string.IsNullOrEmpty(subclassName))
                    SubclassNameChanged?.Invoke(subclassName);
            }
            catch
            {
                // log if needed
            }

            await Task.Delay(_settings.PollIntervalMs, ct);
        }
    }

    // -----------------------------
    // Helper: validate token
    // -----------------------------

    private async Task<bool> ValidateTokenAsync(string accessToken)
    {
        try
        {
            var req = new HttpRequestMessage(
                HttpMethod.Get,
                "https://www.bungie.net/Platform/User/GetMembershipsForCurrentUser/");
            req.Headers.Add("Authorization", $"Bearer {accessToken}");
            var resp = await _httpClient.SendAsync(req);

            return resp.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    // -----------------------------
    // Helper: display name
    // -----------------------------

    private async Task<string> GetDisplayNameAsync(string accessToken)
    {
        var req = new HttpRequestMessage(
            HttpMethod.Get,
            "https://www.bungie.net/Platform/User/GetMembershipsForCurrentUser/");
        req.Headers.Add("Authorization", $"Bearer {accessToken}");

        var resp = await _httpClient.SendAsync(req);
        if (!resp.IsSuccessStatusCode)
            return null;

        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var memberships = doc.RootElement
            .GetProperty("Response")
            .GetProperty("destinyMemberships");

        if (memberships.GetArrayLength() == 0)
            return null;

        var first = memberships[0];
        if (first.TryGetProperty("displayName", out var dn))
            return dn.GetString();

        return null;
    }

    // -----------------------------
    // Helper: subclass name
    // -----------------------------

    private async Task<string> GetEquippedSubclassNameAsync(
        string accessToken,
        string membershipId,
        int membershipType)
    {
        var headers = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://www.bungie.net/Platform/Destiny2/{membershipType}/Profile/{membershipId}/?components=200");
        headers.Headers.Add("Authorization", $"Bearer {accessToken}");

        var resp = await _httpClient.SendAsync(headers);
        if (!resp.IsSuccessStatusCode)
            return null;

        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        var characters = doc.RootElement
            .GetProperty("Response")
            .GetProperty("characters")
            .GetProperty("data");

        if (characters.GetRawText() == "{}")
            return null;

        // Take first character
        string characterId = null;
        foreach (var prop in characters.EnumerateObject())
        {
            characterId = prop.Name;
            break;
        }
        if (characterId == null)
            return null;

        // Get character equipment (subclass bucket)
        var subclassReq = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://www.bungie.net/Platform/Destiny2/{membershipType}/Profile/{membershipId}/Character/{characterId}/?components=205");
        subclassReq.Headers.Add("Authorization", $"Bearer {accessToken}");
        var subclassResp = await _httpClient.SendAsync(subclassReq);

        if (!subclassResp.IsSuccessStatusCode)
            return null;

        var subclassJson = await subclassResp.Content.ReadAsStringAsync();
        using var subclassDoc = JsonDocument.Parse(subclassJson);

        const uint subclassBucketHash = 3284755031;

        uint? equippedSubclassHash = null;
        var items = subclassDoc.RootElement
            .GetProperty("Response")
            .GetProperty("equipment")
            .GetProperty("data")
            .GetProperty("items");

        foreach (var item in items.EnumerateArray())
        {
            if (item.TryGetProperty("bucketHash", out var bucketHashProp) &&
                bucketHashProp.GetUInt32() == subclassBucketHash)
            {
                equippedSubclassHash = item.GetProperty("itemHash").GetUInt32();
                break;
            }
        }

        if (equippedSubclassHash == null)
            return null;

        // Map hash -> subclass name using manifest cache
        var subclasses = await GetCachedSubclassHashesAsync();
        if (subclasses.TryGetValue(equippedSubclassHash.Value.ToString(), out var subclassName))
            return subclassName;

        return "Unknown Subclass";
    }

    // -----------------------------
    // Manifest: cache subclass hashes -> names
    // -----------------------------

    private async Task<Dictionary<string, string>> GetCachedSubclassHashesAsync()
    {
        if (File.Exists(_cacheFilePath))
        {
            var text = await File.ReadAllTextAsync(_cacheFilePath);
            return JsonSerializer.Deserialize<Dictionary<string, string>>(text) ??
                   new Dictionary<string, string>();
        }

        var subclasses = await FetchSubclassHashesAsync();
        var json = JsonSerializer.Serialize(subclasses, new JsonSerializerOptions
        {
            WriteIndented = true
        });
        await File.WriteAllTextAsync(_cacheFilePath, json);
        return subclasses;
    }

    private async Task<Dictionary<string, string>> FetchSubclassHashesAsync()
    {
        var result = new Dictionary<string, string>();

        // 1) Get manifest URL
        var manifestResp = await _httpClient.GetAsync("https://www.bungie.net/Platform/Destiny2/Manifest/");
        manifestResp.EnsureSuccessStatusCode();
        var manifestJson = await manifestResp.Content.ReadAsStringAsync();
        using var manifestDoc = JsonDocument.Parse(manifestJson);

        var paths = manifestDoc.RootElement
            .GetProperty("Response")
            .GetProperty("jsonWorldComponentContentPaths")
            .GetProperty("en");

        string itemDefPath = paths.GetProperty("DestinyInventoryItemDefinition").GetString();
        string fullItemDefUrl = "https://www.bungie.net" + itemDefPath;

        // 2) Download DestinyInventoryItemDefinition
        var itemDefResp = await _httpClient.GetAsync(fullItemDefUrl);
        itemDefResp.EnsureSuccessStatusCode();
        var itemDefJson = await itemDefResp.Content.ReadAsStringAsync();

        using var itemDoc = JsonDocument.Parse(itemDefJson);

        foreach (var prop in itemDoc.RootElement.EnumerateObject())
        {
            var item = prop.Value;
            if (!item.TryGetProperty("itemType", out var itemTypeProp))
                continue;

            // 16 == subclass type
            if (itemTypeProp.GetInt32() == 16)
            {
                if (!item.TryGetProperty("displayProperties", out var displayProps))
                    continue;

                if (displayProps.TryGetProperty("name", out var nameProp))
                {
                    string subclassName = nameProp.GetString();
                    if (item.TryGetProperty("hash", out var hashProp))
                    {
                        string hash = hashProp.GetUInt32().ToString();
                        result[hash] = subclassName;
                    }
                }
            }
        }

        return result;
    }

    // -----------------------------
    // Token persistence
    // -----------------------------

    private bool LoadTokens()
    {
        if (!File.Exists(_tokenFilePath))
            return false;

        try
        {
            var text = File.ReadAllText(_tokenFilePath);
            _tokens = JsonSerializer.Deserialize<Destiny2TokenStore>(text);
            return _tokens != null;
        }
        catch
        {
            return false;
        }
    }

    private void SaveTokens()
    {
        if (_tokens == null)
            return;

        var json = JsonSerializer.Serialize(_tokens, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_tokenFilePath, json);
    }

    public void ClearTokens()
    {
        _tokens = null;
        if (File.Exists(_tokenFilePath))
            File.Delete(_tokenFilePath);

        LoggedInChanged?.Invoke(false);
    }

    public void Dispose()
    {
        _pollCts?.Cancel();
        _httpClient?.Dispose();
    }
}

// -----------------------------
// Artemis module – connects service to data model
// -----------------------------

[PluginFeature(Name = "Destiny 2 Game Module")]
public class Destiny2Module : DataModelModule<Destiny2DataModel>
{
    private readonly PluginSetting<Destiny2Settings> _settings;
    private readonly BungieService _bungieService;

    public Destiny2Module(PluginSettings pluginSettings, IPluginManagementService pluginManagementService)
    {
        _settings = pluginSettings.GetSetting("Destiny2.Settings", new Destiny2Settings());

        string dataFolder = Path.Combine(pluginManagementService.PluginsFolder, "Destiny2");
        _bungieService = new BungieService(_settings.Value, dataFolder);

        _bungieService.DisplayNameChanged += name => DataModel.DisplayName = name;
        _bungieService.SubclassNameChanged += subclass => DataModel.SubclassName = subclass;
        _bungieService.LoggedInChanged += loggedIn => DataModel.IsLoggedIn = loggedIn;
    }

    public override async void Enable()
    {
        // Try auto-login first
        bool ok = await _bungieService.AutoLoginAndStartPollingAsync();
        if (!ok)
        {
            // If auto-login fails, you can expose a command in Artemis UI
            // that calls _bungieService.StartInteractiveLoginAsync()
            DataModel.IsLoggedIn = false;
        }
    }

    public override void Disable()
    {
        _bungieService.StopPolling();
    }

    public override void Update(double deltaTime)
    {
        // No per-frame logic needed; data comes from polling + events
    }

    public override void Dispose()
    {
        _bungieService.Dispose();
        base.Dispose();
    }
}

// -----------------------------
// Plugin entry
// -----------------------------

public class Destiny2Plugin : Plugin<Destiny2Plugin>
{
    public override void Enable()
    {
        // Nothing special here; Artemis will pick up the module
    }

    public override void Disable()
    {
    }
}
