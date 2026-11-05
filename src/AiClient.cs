using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace SuricataChecker
{
    public class AiMessage
    {
        public string Role, Text;   // "user" / "assistant"
        public AiMessage(string role, string text) { Role = role; Text = text; }
    }

    public class AiReply
    {
        public string Text = "", Model = "";
        public int InputTokens, OutputTokens;
        public bool Truncated;
    }

    class AiException : Exception
    {
        public AiException(string message) : base(message) { }
    }

    /// <summary>
    /// Calls the AI providers over their HTTPS APIs (system proxy is used):
    /// Claude – Anthropic Messages API (POST /v1/messages), ChatGPT – OpenAI Chat Completions API (POST /v1/chat/completions).
    /// </summary>
    static class AiClient
    {
        const string AnthropicUrl = "https://api.anthropic.com/v1/", OpenAiUrl = "https://api.openai.com/v1/";
        static readonly HttpClient http;

        static AiClient()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd(Program.AppName + "/1.0");
        }

        public static string ProviderName(AiProvider p) => p == AiProvider.Claude ? "Claude (Anthropic)" : "ChatGPT (OpenAI)";
        public static string KeyUrl(AiProvider p) => p == AiProvider.Claude ? "https://console.anthropic.com/settings/keys" : "https://platform.openai.com/api-keys";
        public static string[] SuggestedModels(AiProvider p) => p == AiProvider.Claude
            ? new[] { "claude-sonnet-5-5", "claude-opus-5-5", "claude-haiku-5-5" }
            : new[] { "gpt-5", "gpt-5-mini" };

        static JavaScriptSerializer Ser() => new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 256 };

        public static async Task<AiReply> SendAsync(AiProvider p, string key, string model, string system, IList<AiMessage> messages, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(key)) throw new AiException("No API key is set for " + ProviderName(p) + " (Settings → AI analyzer).");
            key = key.Trim();   // the same for both providers
            var msgs = messages.Select(m => (object)new Dictionary<string, object> { ["role"] = m.Role, ["content"] = m.Text }).ToList();
            HttpRequestMessage req;
            if (p == AiProvider.Claude)
            {
                var body = new Dictionary<string, object> { ["model"] = model, ["max_tokens"] = 8192, ["system"] = system, ["messages"] = msgs };
                req = new HttpRequestMessage(HttpMethod.Post, AnthropicUrl + "messages") { Content = Json(body) };
                AuthAnthropic(req, key);
            }
            else
            {
                msgs.Insert(0, new Dictionary<string, object> { ["role"] = "system", ["content"] = system });
                var body = new Dictionary<string, object> { ["model"] = model, ["max_completion_tokens"] = 16000, ["messages"] = msgs };
                req = new HttpRequestMessage(HttpMethod.Post, OpenAiUrl + "chat/completions") { Content = Json(body) };
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);
            }

            var res = await SendRawAsync(req, ct);
            var reply = new AiReply { Model = Str(Get(res, "model")) };
            if (p == AiProvider.Claude)
            {
                // content = [{type:"text", text:"…"}, …]
                reply.Text = string.Concat(Arr(Get(res, "content")).Where(b => Str(Get(b, "type")) == "text").Select(b => Str(Get(b, "text"))));
                reply.InputTokens = Int(Get(Get(res, "usage"), "input_tokens"));
                reply.OutputTokens = Int(Get(Get(res, "usage"), "output_tokens"));
                reply.Truncated = Str(Get(res, "stop_reason")) == "max_tokens";
            }
            else
            {
                var choice = Arr(Get(res, "choices")).FirstOrDefault();
                reply.Text = Str(Get(Get(choice, "message"), "content"));
                if (reply.Text.Length == 0) reply.Text = Str(Get(Get(choice, "message"), "refusal"));
                reply.InputTokens = Int(Get(Get(res, "usage"), "prompt_tokens"));
                reply.OutputTokens = Int(Get(Get(res, "usage"), "completion_tokens"));
                reply.Truncated = Str(Get(choice, "finish_reason")) == "length";
            }
            if (reply.Text.Trim().Length == 0)
                throw new AiException(reply.Truncated ? "The model used the whole output limit without an answer – send fewer events or use another model." : "The model returned an empty answer.");
            return reply;
        }

        /// <summary>Models available for the key – also used as the connection test.</summary>
        public static async Task<List<string>> ListModelsAsync(AiProvider p, string key, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(key)) throw new AiException("Enter the API key first.");
            key = key.Trim();
            HttpRequestMessage req;
            if (p == AiProvider.Claude)
            {
                req = new HttpRequestMessage(HttpMethod.Get, AnthropicUrl + "models?limit=100");
                AuthAnthropic(req, key);
            }
            else
            {
                req = new HttpRequestMessage(HttpMethod.Get, OpenAiUrl + "models");
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);
            }
            var res = await SendRawAsync(req, ct);
            var ids = Arr(Get(res, "data")).Select(m => Str(Get(m, "id"))).Where(id => id.Length > 0);
            if (p == AiProvider.OpenAI)   // the list also contains embedding, audio, image… models
                ids = ids.Where(id => Regex.IsMatch(id, @"^(gpt-|o\d|chatgpt-)")
                                      && !Regex.IsMatch(id, "audio|realtime|tts|transcribe|image|search|instruct|embedding|codex", RegexOptions.IgnoreCase));
            return ids.Distinct().OrderByDescending(id => id, StringComparer.OrdinalIgnoreCase).ToList();
        }

        static void AuthAnthropic(HttpRequestMessage req, string key)
        {
            req.Headers.Add("x-api-key", key);
            req.Headers.Add("anthropic-version", "2023-06-01");
        }

        static StringContent Json(object body) => new StringContent(Ser().Serialize(body), Encoding.UTF8, "application/json");

        static async Task<object> SendRawAsync(HttpRequestMessage req, CancellationToken ct)
        {
            HttpResponseMessage resp;
            try { resp = await http.SendAsync(req, ct).ConfigureAwait(false); }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested) { throw new AiException("The request timed out."); }
            catch (HttpRequestException ex) { throw new AiException("Connection to " + req.RequestUri.Host + " failed: " + Innermost(ex).Message); }
            using (resp)
            {
                string text = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                object obj = null;
                try { obj = Ser().DeserializeObject(text); } catch { }
                if (!resp.IsSuccessStatusCode)
                {
                    // both APIs: {"error": {"message": "…", "type": "…"}}
                    string msg = Str(Get(Get(obj, "error"), "message"));
                    if (msg.Length == 0) msg = text.Length > 300 ? text.Substring(0, 300) + "…" : text;
                    throw new AiException(Describe((int)resp.StatusCode) + (msg.Length > 0 ? "\n\n" + msg : ""));
                }
                if (!(obj is Dictionary<string, object>)) throw new AiException("Unexpected response from " + req.RequestUri.Host + ".");
                return obj;
            }
        }

        static string Describe(int status)
        {
            switch (status)
            {
                case 400: return "The request was rejected (400).";
                case 401: return "The API key was rejected (401) – check the key in Settings → AI analyzer.";
                case 403: return "Access denied (403) – the key has no permission for this model or API.";
                case 404: return "Not found (404) – check the model name.";
                case 413: return "Too much data (413) – send fewer events.";
                case 429: return "Rate limit or quota exceeded (429) – wait a moment or check the credit / billing of the API account.";
                case 500: case 502: case 503: case 529: return "The AI service is unavailable or overloaded (" + status + ") – try again later.";
                default: return "The AI service returned an error (" + status + ").";
            }
        }

        static Exception Innermost(Exception ex) { while (ex.InnerException != null) ex = ex.InnerException; return ex; }

        // ---- navigation in the deserialized JSON (Dictionary / object[])
        static object Get(object o, string key) => o is Dictionary<string, object> d && d.TryGetValue(key, out var v) ? v : null;
        static IEnumerable<object> Arr(object o) => o is IEnumerable e && !(o is string) && !(o is IDictionary) ? e.Cast<object>() : Enumerable.Empty<object>();
        static string Str(object o) => o == null ? "" : Convert.ToString(o, System.Globalization.CultureInfo.InvariantCulture);
        static int Int(object o) { try { return o == null ? 0 : Convert.ToInt32(o); } catch { return 0; } }
    }
}
