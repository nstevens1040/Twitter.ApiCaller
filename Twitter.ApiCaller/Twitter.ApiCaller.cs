namespace Twitter
{
    using System;
    using System.IO;
    using System.IO.Compression;
    using System.Net;
    using System.Net.Http;
    using System.Collections;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using System.Text.RegularExpressions;
    using System.Reflection;
    using System.Security.Cryptography;
    using System.Web;
    using mshtml;
    using System.Net.Http.Headers;
    using System.Security;
    using System.Runtime.InteropServices;
    using System.Runtime.CompilerServices;
    using System.Web.Script.Serialization;
    using System.Globalization;
    using System.Management.Automation;
    using Twitter.ApiCaller.Properties;
    internal class JsonObjectTypeResolver : JavaScriptTypeResolver
    {
        public override Type ResolveType(string id) => typeof(Dictionary<string, object>);

        public override string ResolveTypeId(Type type) => string.Empty;
    }
    public class JsonObject
    {
        public JsonObject()
        {
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
            {
                string resourceName = new AssemblyName(args.Name).Name + ".dll";
                string resource = Array.Find(this.GetType().Assembly.GetManifestResourceNames(), element => element.EndsWith(resourceName));
                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource))
                {
                    Byte[] assemblyData = new Byte[stream.Length];
                    stream.Read(assemblyData, 0, assemblyData.Length);
                    return Assembly.Load(assemblyData);
                }
            };
        }
        private const int maxDepthAllowed = 1000;
        public object ConvertFromJson(string input)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }
            ErrorRecord error = (ErrorRecord)null;
            object obj = new JavaScriptSerializer((JavaScriptTypeResolver)new JsonObjectTypeResolver())
            {
                RecursionLimit = 1020,
                MaxJsonLength = int.MaxValue
            }.DeserializeObject(input);
            switch (obj)
            {
                case IDictionary<string, object> _:
                    obj = (object)JsonObject.PopulateFromDictionary(obj as IDictionary<string, object>, out error);
                    break;
                case ICollection<object> _:
                    obj = (object)JsonObject.PopulateFromList(obj as ICollection<object>, out error);
                    break;
            }
            return obj;
        }
        private static ICollection<object> PopulateFromList(
            ICollection<object> list,
            out ErrorRecord error
        )
        {
            error = (ErrorRecord)null;
            List<object> objectList = new List<object>();
            foreach (object obj in (IEnumerable<object>)list)
            {
                switch (obj)
                {
                    case IDictionary<string, object> _:
                        PSObject psObject = JsonObject.PopulateFromDictionary(obj as IDictionary<string, object>, out error);
                        if (error != null)
                        {
                            return (ICollection<object>)null;
                        }
                        objectList.Add((object)psObject);
                        continue;
                    case ICollection<object> _:
                        ICollection<object> objects = JsonObject.PopulateFromList(obj as ICollection<object>, out error);
                        if (error != null)
                        {
                            return (ICollection<object>)null;
                        }
                        objectList.Add((object)objects);
                        continue;
                    default:
                        objectList.Add(obj);
                        continue;
                }
            }
            return (ICollection<object>)objectList.ToArray();
        }
        private static PSObject PopulateFromDictionary(
            IDictionary<string, object> entries,
            out ErrorRecord error
        )
        {
            error = (ErrorRecord)null;
            PSObject psObject1 = new PSObject();
            foreach (KeyValuePair<string, object> entry in (IEnumerable<KeyValuePair<string, object>>)entries)
            {
                PSPropertyInfo property = psObject1.Properties[entry.Key];
                if (property != null)
                {
                    string message = string.Format((IFormatProvider)CultureInfo.InvariantCulture, webCmdletStrings.DuplicateKeysInJsonString, (object)property.Name, (object)entry.Key);
                    error = new ErrorRecord((Exception)new InvalidOperationException(message), "DuplicateKeysInJsonString", ErrorCategory.InvalidOperation, (object)null);
                    return (PSObject)null;
                }
                if (entry.Value is IDictionary<string, object>)
                {
                    PSObject psObject2 = JsonObject.PopulateFromDictionary(entry.Value as IDictionary<string, object>, out error);
                    if (error != null)
                        return (PSObject)null;
                    psObject1.Properties.Add((PSPropertyInfo)new PSNoteProperty(entry.Key, (object)psObject2));
                }
                else if (entry.Value is ICollection<object>)
                {
                    ICollection<object> objects = JsonObject.PopulateFromList(entry.Value as ICollection<object>, out error);
                    if (error != null)
                        return (PSObject)null;
                    psObject1.Properties.Add((PSPropertyInfo)new PSNoteProperty(entry.Key, (object)objects));
                }
                else
                {
                    psObject1.Properties.Add((PSPropertyInfo)new PSNoteProperty(entry.Key, entry.Value));
                }
            }
            return psObject1;
        }
    }
    public class Json
    {
        public static object Convert(string inputJson)
        {
            JsonObject jo = new JsonObject();
            object deserialized = jo.ConvertFromJson(inputJson);
            return deserialized;
        }
    }

    public class Cred
    {
        public TaskAwaiter<Task<Cred>> GetAwaiter()
        {
            return new TaskAwaiter<Task<Cred>>();
        }
        public CookieCollection CookieCollection = new CookieCollection();
        public string guest_token
        {
            get;
            set;
        }
        public RetObject FrontPageResponse
        {
            get;
            set;
        }
        public string access_token_response
        {
            get;
            set;
        }
        public string GenericBearer
        {
            get;
            set;
        }
        public string appBearer
        {
            get;
            set;
        }
        public string x_csrf_token
        {
            get;
            set;
        }
        public string screen_name
        {
            get;
            set;
        }
        public string user_id
        {
            get;
            set;
        }
        public string oauth_token
        {
            get;
            set;
        }
        public string oauth_secret
        {
            get;
            set;
        }
        public string authorization
        {
            get;
            set;
        }
    }
    public class Utils
    {

        public string oauth_consumer_key;
        public string oauth_consumer_secret;
        public Cred TwitterCredentials = new Cred();
        public dynamic user;
        public string twid;
        public string tweetsQueryUri;
        public string timeLineMediaUri;
        public dynamic timelineMedia;
        public Int32 userMediaCount;
        public List<dynamic> timeLineMediaTweets = new List<dynamic>();
        public string DownloadFolder;
        public Utils()
        {
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
            {
                string resourceName = new AssemblyName(args.Name).Name + ".dll";
                string resource = Array.Find(this.GetType().Assembly.GetManifestResourceNames(), element => element.EndsWith(resourceName));
                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource))
                {
                    Byte[] assemblyData = new Byte[stream.Length];
                    stream.Read(assemblyData, 0, assemblyData.Length);
                    return Assembly.Load(assemblyData);
                }
            };
        }
        public Utils(string consumer_key, string consumer_secret)
        {
            this.oauth_consumer_key = consumer_key;
            this.oauth_consumer_secret = consumer_secret;
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
            {
                string resourceName = new AssemblyName(args.Name).Name + ".dll";
                string resource = Array.Find(this.GetType().Assembly.GetManifestResourceNames(), element => element.EndsWith(resourceName));
                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource))
                {
                    Byte[] assemblyData = new Byte[stream.Length];
                    stream.Read(assemblyData, 0, assemblyData.Length);
                    return Assembly.Load(assemblyData);
                }
            };
        }
        public void SetDownloadFolder()
        {
            this.DownloadFolder = Environment.GetEnvironmentVariable("userprofile") + "\\Desktop\\TWDOWNLOAD\\" + Math.Round((DateTime.Now - DateTime.Parse("1970-01-01")).TotalSeconds).ToString() + "\\" + this.user.data.username.ToString() + "\\";
            if (!Directory.Exists(this.DownloadFolder))
            {
                Directory.CreateDirectory(this.DownloadFolder);
            }
        }
        private string oauth_token
        {
            get;
            set;
        }
        private string oauth_secret
        {
            get;
            set;
        }
        private string oauth_verifier
        {
            get;
            set;
        }
        private string VerifierUri
        {
            get;
            set;
        }
        private string ResponseText
        {
            get;
            set;
        }
        //private string authorization
        //{
        //    get;
        //    set;
        //}
        private string oauth_signature
        {
            get;
            set;
        }
        private string oauth_version
        {
            get;
            set;
        }
        private string oauth_timestamp
        {
            get;
            set;
        }
        private string oauth_signature_method
        {
            get;
            set;
        }
        private string oauth_nonce
        {
            get;
            set;
        }
        private RetObject authorize_response
        {
            get;
            set;
        }
        private string oauth_callback_confirmed
        {
            get;
            set;
        }
        [DllImport("ole32.dll")]
        private static extern void CoTaskMemFree(IntPtr ptr);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDUI_INFO
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }
        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        private static extern int CredUIPromptForWindowsCredentials(
            ref CREDUI_INFO notUsedHere,
            int authError,
            ref uint authPackage,
            IntPtr InAuthBuffer,
            uint InAuthBufferSize,
            out IntPtr refOutAuthBuffer,
            out uint refOutAuthBufferSize,
            ref bool fSave,
            int flags
        );
        [DllImport("credui.dll", CharSet = CharSet.Unicode)]
        private static extern bool CredUnPackAuthenticationBuffer(
            int dwFlags,
            IntPtr pAuthBuffer,
            uint cbAuthBuffer,
            StringBuilder pszUserName,
            ref int pcchMaxUserName,
            StringBuilder pszDomainName,
            ref int pcchMaxDomainame,
            StringBuilder pszPassword,
            ref int pcchMaxPassword
        );
        private static SecureString GetCredential(string domain = null)
        {
            CREDUI_INFO credui = new CREDUI_INFO();
            credui.pszCaptionText = "Enter your network credentials";
            credui.pszMessageText = "Enter your credentials to connect to: " + domain;
            credui.cbSize = Marshal.SizeOf(credui);
            uint authPackage = 0;
            IntPtr outCredBuffer = new IntPtr();
            uint outCredSize;
            bool save = false;
            int result = CredUIPromptForWindowsCredentials(ref credui, 0, ref authPackage, IntPtr.Zero, 0, out outCredBuffer, out outCredSize, ref save, 1);
            var usernameBuf = new StringBuilder(100);
            var passwordBuf = new StringBuilder(100);
            var domainBuf = new StringBuilder(100);
            int maxUserName = 100;
            int maxDomain = 100;
            int maxPassword = 100;
            SecureString sec = new SecureString();
            if (result == 0)
            {
                if (CredUnPackAuthenticationBuffer(0, outCredBuffer, outCredSize, usernameBuf, ref maxUserName, domainBuf, ref maxDomain, passwordBuf, ref maxPassword))
                {
                    CoTaskMemFree(outCredBuffer);
                    (Convert.ToBase64String(
                        System.Security.Cryptography.ProtectedData.Protect(
                            Encoding.UTF8.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(usernameBuf.ToString() + (Char)128 + passwordBuf.ToString()))),
                            null,
                            DataProtectionScope.LocalMachine
                        )
                    )).ToCharArray().ToList().ForEach((i) =>
                    {
                        sec.AppendChar(i);
                    });
                    return sec;
                }
                else
                {
                    return sec;
                }
            }
            else
            {
                return sec;
            }
        }
        public string MakeAuthorizationHeader(
            string oauth_consumer_key = null,
            string oauth_consumer_secret = null,
            string oauth_token = null,
            string oauth_secret = null,
            string target_uri = "https://api.twitter.com/oauth/request_token",
            string method = "POST"
        )
        {
            List<string> requestParameters = new List<string>();
            List<string> requestParametersForHeader = new List<string>();
            string nonce = new Random().Next(1000000000).ToString();
            string timeStamp = Convert.ToInt64((DateTime.UtcNow - DateTime.Parse(@"1970-01-01")).TotalSeconds).ToString();
            if (String.IsNullOrEmpty(oauth_token))
            {
                requestParameters = new List<string>
                {
                    "oauth_consumer_key=" + this.oauth_consumer_key,
                    "oauth_signature_method=HMAC-SHA1",
                    "oauth_timestamp=" + timeStamp,
                    "oauth_nonce=" + nonce,
                    "oauth_version=1.0"
                };
            }
            else
            {
                requestParameters = new List<string>
                {
                    "oauth_consumer_key=" + this.oauth_consumer_key,
                    "oauth_token=" + oauth_token,
                    "oauth_signature_method=HMAC-SHA1",
                    "oauth_timestamp=" + timeStamp,
                    "oauth_nonce=" + nonce,
                    "oauth_version=1.0"
                };
            }
            Uri requestUri = new Uri(target_uri, UriKind.Absolute);
            string queryString = requestUri.Query;
            Dictionary<string, string> parameters = new Dictionary<string, string>();
            if (!String.IsNullOrWhiteSpace(queryString))
            {
                if (queryString.StartsWith("?"))
                {
                    queryString = queryString.Remove(0, 1);
                }

                if (!String.IsNullOrEmpty(queryString))
                {
                    foreach (string s in queryString.Split('&'))
                    {
                        if (!String.IsNullOrEmpty(s) && !s.StartsWith("oauth_"))
                        {
                            if (s.IndexOf('=') > -1)
                            {
                                parameters.Add(s.Split('=')[0], s.Split('=')[1]);
                            }
                            else
                            {
                                parameters.Add(s, String.Empty);
                            }
                        }
                    }
                }
                foreach (KeyValuePair<string, string> kvp in parameters)
                {
                    requestParameters.Add(kvp.Key + "=" + kvp.Value);
                }
            }
            List<string> sortedList = new List<string>(requestParameters);
            sortedList.Sort();
            string requestParametersSortedString = String.Join("&", sortedList);
            Uri uri = new Uri(target_uri, UriKind.Absolute);
            string host = uri.Scheme + @"://" + uri.Host;
            if (!(uri.Scheme == "http" && uri.Port == 80 || uri.Scheme == "https" && uri.Port == 443))
            {
                host += ":" + uri.Port;
            }
            target_uri = host + uri.AbsolutePath;
            string signatureBaseString = method.ToUpper() + "&" + Uri.EscapeDataString(target_uri) + "&" + Uri.EscapeDataString(requestParametersSortedString);
            HMACSHA1 hmacsha1 = new HMACSHA1();
            string key;
            if (String.IsNullOrEmpty(oauth_secret))
            {
                key = Uri.EscapeDataString(oauth_consumer_secret) + "&" + "";
            }
            else
            {
                key = Uri.EscapeDataString(oauth_consumer_secret) + "&" + Uri.EscapeDataString(oauth_secret);
            }
            hmacsha1.Key = Encoding.ASCII.GetBytes(key);
            byte[] dataBuffer = Encoding.ASCII.GetBytes(signatureBaseString);
            byte[] hashBytes = hmacsha1.ComputeHash(dataBuffer);
            string signature = Convert.ToBase64String(hashBytes);
            if (String.IsNullOrEmpty(oauth_token))
            {
                requestParametersForHeader = new List<string>
                {
                    "oauth_consumer_key=\"" + this.oauth_consumer_key + "\"",
                    "oauth_signature_method=\"HMAC-SHA1\"",
                    "oauth_timestamp=\"" + timeStamp + "\"",
                    "oauth_nonce=\"" + nonce + "\"",
                    "oauth_version=\"1.0\"",
                    "oauth_signature=\"" + Uri.EscapeDataString(signature) + "\""
                };
            }
            else
            {
                requestParametersForHeader = new List<string>
                {
                    "oauth_consumer_key=\"" + this.oauth_consumer_key + "\"",
                    "oauth_token=\"" + oauth_token + "\"",
                    "oauth_signature_method=\"HMAC-SHA1\"",
                    "oauth_timestamp=\"" + timeStamp + "\"",
                    "oauth_nonce=\"" + nonce + "\"",
                    "oauth_version=\"1.0\"",
                    "oauth_signature=\"" + Uri.EscapeDataString(signature) + "\""
                };

            }
            string OAuthHeader = "OAuth " + String.Join(",", requestParametersForHeader);
            return OAuthHeader;
        }
        public object SubmitOAuth2Request(
            string targetUri,
            string method = null
        )
        {
            HttpMethod httpMethod = null;
            if (!String.IsNullOrEmpty(method))
            {
                Dictionary<string, HttpMethod> methods = new Dictionary<string, HttpMethod>()
                {
                    { "GET", HttpMethod.Get },
                    { "POST", HttpMethod.Post },
                    { "OPTIONS", HttpMethod.Options },
                    { "PUT", HttpMethod.Put },
                    { "DELETE", HttpMethod.Delete },
                    { "TRACE", HttpMethod.Trace },
                    { "HEAD", HttpMethod.Head }
                };
                httpMethod = methods[method.ToUpper()];
            }
            else
            {
                httpMethod = nslist.nslist.NameSpaceList.Where(i =>
                {
                    return (i.endpoint.Match(targetUri.Split('?').FirstOrDefault()).Success);
                }).FirstOrDefault().method;
            }
            OrderedDictionary userHeaders = new OrderedDictionary();
            userHeaders.Add("method", httpMethod.ToString().ToUpper());
            userHeaders.Add("authority", "twitter.com");
            userHeaders.Add("scheme", "https");
            userHeaders.Add("pragma", "no-cache");
            userHeaders.Add("cache-control", "no-cache");
            userHeaders.Add("dnt", "1");
            userHeaders.Add("x-twitter-client-language", "en");
            userHeaders.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36");
            userHeaders.Add("x-twitter-auth-type", "OAuth2Session");
            userHeaders.Add("x-twitter-active-user", "yes");
            userHeaders.Add("accept", "*/*");
            userHeaders.Add("sec-fetch-site", "same-origin");
            userHeaders.Add("sec-fetch-mode", "cors");
            userHeaders.Add("sec-fetch-dest", "empty");
            userHeaders.Add("accept-encoding", "gzip, deflate");
            userHeaders.Add("accept-language", "en-US,en;q=0.9");
            userHeaders.Add("authorization", @"Bearer " + this.TwitterCredentials.appBearer);
            userHeaders.Add("x-csrf-token", this.TwitterCredentials.x_csrf_token);
            RetObject response = HttpRequest.Send(
                targetUri,
                httpMethod,
                userHeaders,
                this.TwitterCredentials.CookieCollection
            );
            object deserialized = null;
            if (new Regex(@"\{""errors""").Match(response.ResponseText).Success)
            {
                OrderedDictionary guestHeaders = new OrderedDictionary();
                guestHeaders.Add("x-guest-token", this.TwitterCredentials.guest_token);
                guestHeaders.Add("authorization", "Bearer " + this.TwitterCredentials.GenericBearer);
                guestHeaders.Add("x-csrf-token", this.TwitterCredentials.x_csrf_token);
                guestHeaders.Add("method", httpMethod.ToString().ToUpper());
                guestHeaders.Add("authority", "twitter.com");
                guestHeaders.Add("scheme", "https");
                guestHeaders.Add("pragma", "no-cache");
                guestHeaders.Add("cache-control", "no-cache");
                guestHeaders.Add("dnt", "1");
                guestHeaders.Add("x-twitter-client-language", "en");
                guestHeaders.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36");
                guestHeaders.Add("x-twitter-auth-type", "OAuth2Session");
                guestHeaders.Add("x-twitter-active-user", "yes");
                guestHeaders.Add("accept", "*/*");
                guestHeaders.Add("sec-fetch-site", "same-origin");
                guestHeaders.Add("sec-fetch-mode", "cors");
                guestHeaders.Add("sec-fetch-dest", "empty");
                guestHeaders.Add("accept-encoding", "gzip, deflate");
                guestHeaders.Add("accept-language", "en-US,en;q=0.9");
                response = HttpRequest.Send(
                    targetUri,
                    httpMethod,
                    guestHeaders,
                    this.TwitterCredentials.CookieCollection
                );
                deserialized = Json.Convert(response.ResponseText);
                return deserialized;
            }
            else
            {
                deserialized = Json.Convert(response.ResponseText);
                return deserialized;
            }
        }
        public object SubmitOAuth1Request(
            string targetUri = "https://api.twitter.com/oauth/request_token",
            string method = null,
            string oauth_consumer_key = null,
            string oauth_consumer_secret = null,
            string oauth_token = null,
            string oauth_secret = null
        )
        {
            HttpMethod httpMethod = null;
            string auth = String.Empty;
            OrderedDictionary headers = new OrderedDictionary();
            RetObject req = null;
            if (!String.IsNullOrEmpty(oauth_consumer_key))
            {
                if (String.IsNullOrEmpty(this.oauth_consumer_key))
                {
                    this.oauth_consumer_key = oauth_consumer_key;
                }
            }
            if (!String.IsNullOrEmpty(oauth_consumer_secret))
            {
                if (String.IsNullOrEmpty(this.oauth_consumer_secret))
                {
                    this.oauth_consumer_secret = oauth_consumer_secret;
                }
            }
            if (!String.IsNullOrEmpty(oauth_token))
            {
                if (String.IsNullOrEmpty(this.TwitterCredentials.oauth_token))
                {
                    this.TwitterCredentials.oauth_token = oauth_token;
                }
            }
            if (!String.IsNullOrEmpty(oauth_secret))
            {
                if (String.IsNullOrEmpty(this.TwitterCredentials.oauth_secret))
                {
                    this.TwitterCredentials.oauth_secret = oauth_secret;
                }
            }
            if (targetUri.Contains("oauth"))
            {
                httpMethod = HttpMethod.Post;
                auth = this.MakeAuthorizationHeader(this.oauth_consumer_key, this.oauth_consumer_secret, this.TwitterCredentials.oauth_token, this.TwitterCredentials.oauth_secret, targetUri, httpMethod.ToString().ToUpper());
                this.oauth_nonce = auth.Split(',').ToList().Where(i => (new Regex(@"nonce")).Match(i).Success).FirstOrDefault().Split('"')[1];
                this.oauth_signature = auth.Split(',').ToList().Where(i => (new Regex(@"signature")).Match(i).Success).FirstOrDefault().Split('"')[1];
                this.oauth_timestamp = auth.Split(',').ToList().Where(i => (new Regex(@"timestamp")).Match(i).Success).FirstOrDefault().Split('"')[1];
                this.TwitterCredentials.authorization = (new Regex(@"(\n)$")).Replace((new Regex(@",(\s*)").Replace(auth, ((Char)44).ToString())), String.Empty);
                headers = new OrderedDictionary();
                headers.Add("Authorization", this.TwitterCredentials.authorization);
                req = HttpRequest.Send(
                    targetUri,
                    httpMethod,
                    headers,
                    null,
                    "application/x-www-form-urlencoded"
                );
            }
            else
            {
                if (!String.IsNullOrEmpty(method))
                {
                    Dictionary<string, HttpMethod> methods = new Dictionary<string, HttpMethod>()
                    {
                        { "GET", HttpMethod.Get },
                        { "POST", HttpMethod.Post },
                        { "OPTIONS", HttpMethod.Options },
                        { "PUT", HttpMethod.Put },
                        { "DELETE", HttpMethod.Delete },
                        { "TRACE", HttpMethod.Trace },
                        { "HEAD", HttpMethod.Head }
                    };
                    httpMethod = methods[method.ToUpper()];
                }
                else
                {
                    httpMethod = nslist.nslist.NameSpaceList.Where(i =>
                    {
                        return (i.endpoint.Match(targetUri.Split('?').FirstOrDefault()).Success);
                    }).FirstOrDefault().method;
                }
                auth = this.MakeAuthorizationHeader(this.oauth_consumer_key, this.oauth_consumer_secret, this.TwitterCredentials.oauth_token, this.TwitterCredentials.oauth_secret, targetUri, httpMethod.ToString().ToUpper());
                this.oauth_nonce = auth.Split(',').ToList().Where(i => (new Regex(@"nonce")).Match(i).Success).FirstOrDefault().Split('"')[1];
                this.oauth_signature = auth.Split(',').ToList().Where(i => (new Regex(@"signature")).Match(i).Success).FirstOrDefault().Split('"')[1];
                this.oauth_timestamp = auth.Split(',').ToList().Where(i => (new Regex(@"timestamp")).Match(i).Success).FirstOrDefault().Split('"')[1];
                this.TwitterCredentials.authorization = (new Regex(@"(\n)$")).Replace((new Regex(@",(\s*)").Replace(auth, ((Char)44).ToString())), String.Empty);
                headers = new OrderedDictionary();
                headers.Add("Authorization", this.TwitterCredentials.authorization);
                headers.Add("x-csrf-token", this.TwitterCredentials.x_csrf_token);
                req = HttpRequest.Send(
                    targetUri,
                    httpMethod,
                    headers,
                    this.TwitterCredentials.CookieCollection,
                    "application/x-www-form-urlencoded"
                );
            }
            if (String.IsNullOrEmpty(this.TwitterCredentials.oauth_token))
            {
                req.ResponseText.Split((Char)38).ToList().ForEach((i) => {
                    string k = i.Split((Char)61).ToList()[0];
                    string v = i.Split((Char)61).ToList()[1];
                    switch (k)
                    {
                        case "oauth_token":
                            this.oauth_token = v;
                            break;
                        case "oauth_token_secret":
                            this.oauth_secret = v;
                            break;
                        case "oauth_callback_confirmed":
                            this.oauth_callback_confirmed = v;
                            break;
                        default:
                            break;
                    }
                });
                this.oauth_version = "1.0";
                this.oauth_signature_method = "HMAC-SHA1";
                return new object();
            }
            else
            {
                object deserialized = Json.Convert(req.ResponseText);
                return deserialized;
            }
        }
        public void CreateTwitterCredentialObject()
        {
            RetObject re = new RetObject();
            if (!String.IsNullOrEmpty(this.oauth_consumer_key) & !String.IsNullOrEmpty(this.oauth_consumer_secret))
            {
                object TwitterCredentials = this.SubmitOAuth1Request();
                re = HttpRequest.Send(
                    "https://api.twitter.com/oauth/authorize?oauth_token=" + this.oauth_token,
                    HttpMethod.Get
                );
                OrderedDictionary headers = new OrderedDictionary()
                {
                    {"Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(this.oauth_consumer_key + (Char)58 + this.oauth_consumer_secret)) }
                };
                RetObject bas = HttpRequest.Send(
                    "https://api.twitter.com/oauth2/token",
                    HttpMethod.Post,
                    headers,
                    null,
                    "application/x-www-form-urlencoded",
                    "grant_type=client_credentials"
                );
                if (bas != null)
                {
                    //JsonDocument basResponse = this.ConvertFromJson(bas.ResponseText);
                    dynamic basResponse = Json.Convert(bas.ResponseText);
                    this.TwitterCredentials.appBearer = basResponse.access_token.ToString();
                }
            }
            OrderedDictionary guest_h = new OrderedDictionary();
            guest_h.Add("authorization", "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA");
            guest_h.Add("x-csrf-token", this.TwitterCredentials.x_csrf_token);
            guest_h.Add("x-guest-token", this.TwitterCredentials.guest_token);
            RetObject guest_request = HttpRequest.Send(
                "https://api.twitter.com/1.1/guest/activate.json",
                HttpMethod.Post,
                guest_h,
                this.TwitterCredentials.CookieCollection,
                "application/x-www-form-urlencoded"
            );
            dynamic guest_response = Json.Convert(guest_request.ResponseText);
            this.TwitterCredentials.guest_token = guest_response.guest_token.ToString();
            List<string> bodyra = new List<string>();
            string form = new Regex(@">(\s*)<").Replace((new Regex(@"<form(.*)/form>").Match(new Regex(@"(\n)").Replace(re.ResponseText, String.Empty)).Value), ">\n$1<");
            SecureString sec = GetCredential(@"Twitter.com");
            form.Split((Char)10).ToList().Where(i => (new Regex(@"(.*)input(.*)")).Match(i).Success).ToList().ForEach((i) =>
            {
                if (!String.IsNullOrEmpty(i))
                {
                    string n = String.Empty;
                    string v = String.Empty;
                    bool na = false;
                    bool va = false;
                    i.Split(' ').ToList().Where(a => (new Regex(@"^name")).Match(a).Success || (new Regex(@"^value")).Match(a).Success).ToList().ForEach((b) =>
                    {
                        if ((new Regex(@"^name")).Match(b).Success)
                        {
                            n = b.Split('"')[1];
                            na = true;
                        }
                        if ((new Regex(@"^value")).Match(b).Success)
                        {
                            v = b.Split('"')[1];
                            va = true;
                        }
                        if ((na && va) || n.Equals("ui_metrics") || v.Equals("Authorize"))
                        {
                            switch (n)
                            {
                                case @"session[username_or_email]":
                                    bodyra.Add(
                                        HttpUtility.UrlEncode(n) + '=' + HttpUtility.UrlEncode(
                                            Encoding.UTF8.GetString(
                                                Convert.FromBase64String(
                                                    Encoding.UTF8.GetString(
                                                        System.Security.Cryptography.ProtectedData.Unprotect(
                                                            Convert.FromBase64String(new NetworkCredential(String.Empty, sec).Password),
                                                            null,
                                                            System.Security.Cryptography.DataProtectionScope.LocalMachine
                                                        )
                                                    )
                                                )
                                            ).Split((char)128).FirstOrDefault()
                                        )
                                    );
                                    break;
                                case @"session[password]":
                                    bodyra.Add(
                                        HttpUtility.UrlEncode(n) + '=' + HttpUtility.UrlEncode(
                                            Encoding.UTF8.GetString(
                                                Convert.FromBase64String(
                                                    Encoding.UTF8.GetString(
                                                        System.Security.Cryptography.ProtectedData.Unprotect(
                                                            Convert.FromBase64String(new NetworkCredential(String.Empty, sec).Password),
                                                            null,
                                                            System.Security.Cryptography.DataProtectionScope.LocalMachine
                                                        )
                                                    )
                                                )
                                            ).Split((char)128).Last()
                                        )
                                    );
                                    break;
                                case @"remember_me":
                                    break;
                                case @"ui_metrics":
                                    bodyra.Add(HttpUtility.UrlEncode(n) + '=' + HttpUtility.UrlEncode("{\"rf\":{\"ac7fbc40d59caa163d33ab355fabddd25e18f8f380009f25a437df88449d7d67\":103,\"af568052b668874ea98177ed031f0119e35039113d68bc9c5466b9b3edb928c9\":88,\"a30691b97b3b07e096ec5deca36520bcde0f234bcd2b82970da976d8d5760b2a\":156,\"aae0831b40e56fee6bcab29821fdccfd64f4872ef783975028b219e84693f5fb\":8},\"s\":\"pFSxdD5k7_ZnhY74-PK7a041Xw8_NpFyiThSDUlDpne0HUnpCRoBjEHT5TjMVguvKCW_r0qQfNCjW576Nd7csWvvegahyKvWM5-m1EORxZVOlJvyuf1aorCPEdYL26LbTVkyoVtJAoSJFxOJlsdObzW_2jhrqchlnhsnKz-IWvWck7z_yfqOvGdEAPEFgEFZXPPMs-uW62Y9xKkaHA56oZYAOLJbPuqjq0sOOlaO3uzWaXN2Tl6Dj-sp9ybdS6ZgRJzya7b0J6vFUxD2Gz1LUkzIcc7S8Ab5vBqI8RvLEN1j3wUoVPVSycDC3ULtb62AW_Wljg-ucbI4cceJ9RQscQAAAXbdxVCh\"}"));
                                    break;
                                case @"cancel":
                                    break;
                                default:
                                    bodyra.Add(HttpUtility.UrlEncode(n) + '=' + HttpUtility.UrlEncode(v));
                                    break;
                            }
                            if (v.Equals("Authorize"))
                            {
                                bodyra.Add('=' + HttpUtility.UrlEncode("Authorize app"));
                            }
                        }
                    });
                }
            });
            string body = String.Join(((Char)38).ToString(), bodyra);
            RetObject ret = HttpRequest.Send(
                "https://api.twitter.com/oauth/authorize",
                HttpMethod.Post,
                null,
                re.CookieCollection,
                "application/x-www-form-urlencoded",
                body
            );
            this.authorize_response = ret;
            OrderedDictionary twi_headers = new OrderedDictionary();
            ret.HttpResponseMessage.Headers.ToList().ForEach((i) =>
            {
                twi_headers.Add(i.Key, i.Value);
            });
            RetObject twi = HttpRequest.Send(
                "https://twitter.com/",
                HttpMethod.Get,
                twi_headers,
                ret.CookieCollection
            );
            this.TwitterCredentials.FrontPageResponse = twi;
            this.TwitterCredentials.CookieCollection = twi.CookieCollection;
            Cookie[] cks = new Cookie[twi.CookieCollection.Count];
            twi.CookieCollection.CopyTo(cks, 0);
            this.TwitterCredentials.x_csrf_token = cks.Where(i => i.Name.Equals("ct0")).FirstOrDefault().Value;
            this.TwitterCredentials.GenericBearer = @"AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";
            this.oauth_token = new Uri(HttpUtility.HtmlDecode(ret.ResponseText.Split('"').ToList().Where(i => (new Regex(@"^http(.+)oauth_token(.+)oauth_verifier(.+)")).Match(i).Success).FirstOrDefault())).Query.Split((Char)38).FirstOrDefault().Split((Char)61).Last();
            this.oauth_verifier = new Uri(HttpUtility.HtmlDecode(ret.ResponseText.Split('"').ToList().Where(i => (new Regex(@"^http(.+)oauth_token(.+)oauth_verifier(.+)")).Match(i).Success).FirstOrDefault())).Query.Split((Char)38).Last().Split((Char)61).Last();
            this.VerifierUri = "https://api.twitter.com/oauth/access_token?oauth_token=" + this.oauth_token + "&oauth_verifier=" + this.oauth_verifier;
            this.TwitterCredentials.access_token_response = new WebClient().DownloadString(this.VerifierUri);
            this.TwitterCredentials.access_token_response.Split((Char)38).ToList().ForEach((i) => {
                string ke = i.Split((Char)61)[0];
                string va = i.Split((Char)61)[1];
                switch (ke)
                {
                    case "oauth_token":
                        this.TwitterCredentials.oauth_token = va;
                        break;
                    case "oauth_token_secret":
                        this.TwitterCredentials.oauth_secret = va;
                        break;
                    case "user_id":
                        this.TwitterCredentials.user_id = va;
                        break;
                    case "screen_name":
                        this.TwitterCredentials.screen_name = va;
                        break;
                    default:
                        break;
                }
            });
        }
        public void RequestTimeLineMedia()
        {
            PSObject preTimeLineRequest = (PSObject)this.SubmitOAuth2Request("https://api.twitter.com/2/timeline/media/" + this.twid + ".json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_composer_source=true&include_ext_alt_text=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweets=true&count=20&ext=mediaStats%2CcameraMoment");
            this.userMediaCount = Int32.Parse(((PSObject)((PSObject)((PSObject)preTimeLineRequest.Properties.ToList().Where(i =>
            {
                return (i.Name.Equals("globalObjects"));
            }).FirstOrDefault().Value).Properties.ToList().Where(i =>
            {
                return (i.Name.Equals("users"));
            }).FirstOrDefault().Value).Properties.ToList().Where(i =>
            {
                return (i.Name.Equals(this.twid));
            }).FirstOrDefault().Value).Properties.ToList().Where(i =>
            {
                return (i.Name.Equals("media_count"));
            }).FirstOrDefault().Value.ToString());
            this.timeLineMediaUri = "https://api.twitter.com/2/timeline/media/" + this.twid + ".json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_composer_source=true&include_ext_alt_text=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweets=true&count=" + this.userMediaCount.ToString() + "&ext=mediaStats%2CcameraMoment";
            this.timeLineMediaTweets = new List<dynamic>();
            this.timelineMedia = (dynamic)this.SubmitOAuth2Request(this.timeLineMediaUri);
            ((PSObject)((PSObject)((PSObject)this.timelineMedia).Properties.ToList().Where(i =>
            {
                return (i.Name.Equals("globalObjects"));
            }).FirstOrDefault().Value).Properties.ToList().Where(i =>
            {
                return (i.Name.Equals("tweets"));
            }).FirstOrDefault().Value).Properties.ToList().ForEach(i =>
            {
                this.timeLineMediaTweets.Add(i.Value);
            });
        }
        public string[] GetMediaUriFromTweetObject(dynamic tweet)
        {
            List<dynamic> variants = new List<dynamic>();
            List<PSObject> userMedia = new List<PSObject>();
            dynamic media = null;
            IEnumerable<dynamic> pic_media = null;
            dynamic video_info = null;
            List<string> image_uris = new List<string>();
            string[] uris = new string[0];
            try
            {
                media = tweet.extended_entities.media[0];
            }
            catch { }
            if (media != null)
            {
                try
                {
                    video_info = media.video_info;
                }
                catch { }
                if (video_info != null)
                {
                    IEnumerable<dynamic> variant_list = video_info.variants;
                    variant_list.ToList().ForEach(i =>
                    {
                        if (i.bitrate != null)
                        {
                            variants.Add(i);
                        }
                    });
                    variants.Sort((x, y) => Int32.Parse(x.bitrate.ToString()).CompareTo(Int32.Parse(y.bitrate.ToString())));
                    uris = new string[1];
                    uris[0] = variants.Last().url.ToString();
                    return uris;
                }
                else
                {
                    try
                    {
                        pic_media = tweet.extended_entities.media;
                        pic_media.ToList().ForEach(i =>
                        {
                            image_uris.Add(i.media_url_https);
                        });
                    }
                    catch { }
                    if (image_uris.Count > 0)
                    {
                        uris = new string[image_uris.Count];
                        for (int i = 0; i < image_uris.Count; i++)
                        {
                            uris[i] = image_uris[i];
                        }
                        return uris;
                    }
                    else
                    {
                        return uris;
                    }
                }
            }
            else
            {
                return uris;
            }
        }
        public void GetUser(string username, bool create_folder = false)
        {
            this.user = (dynamic)this.SubmitOAuth1Request("https://api.twitter.com/2/users/by/username/" + username);
            this.twid = user.data.id;
            this.tweetsQueryUri = "https://api.twitter.com/2/users/" + this.twid + "/tweets?expansions=attachments.poll_ids,attachments.media_keys,author_id,entities.mentions.username,geo.place_id,in_reply_to_user_id,referenced_tweets.id,referenced_tweets.id.author_id&tweet.fields=attachments,author_id,context_annotations,conversation_id,created_at,entities,geo,id,in_reply_to_user_id,lang,possibly_sensitive,public_metrics,referenced_tweets,reply_settings,source,text,withheld&user.fields=created_at,description,entities,id,location,name,pinned_tweet_id,profile_image_url,protected,public_metrics,url,username,verified,withheld&place.fields=contained_within,country,country_code,full_name,geo,id,name,place_type&poll.fields=duration_minutes,end_datetime,id,options,voting_status&media.fields=duration_ms,height,media_key,preview_image_url,type,url,width,public_metrics&max_results=100";
            if (create_folder)
            {
                this.SetDownloadFolder();
            }
        }
        public async Task DownloadAsync(string uri)
        {
            await Task.Factory.StartNew(() =>
            {
                string file = this.DownloadFolder + new Uri(uri).Segments.ToList().Where(i => { return (new Regex(@"(mp4|jpg|png|gif)").Match(i).Success); }).FirstOrDefault();
                new WebClient() { Proxy = null }.DownloadFile(
                    uri,
                    file
                );
            }, TaskCreationOptions.None);
        }
        private static HTMLDocument DOMParser(string responseText)
        {
            HTMLDocument domobj = new HTMLDocument();
            IHTMLDocument2 doc2 = (IHTMLDocument2)domobj;
            doc2.write(new object[] { responseText });
            doc2.close();
            return domobj;
        }
        private static CookieCollection SetCookieParser(List<string> setCookie, CookieCollection cooks, CookieCollection initCookies)
        {
            List<Exception> ex = new List<Exception>();
            List<Hashtable> rckevalues = new List<Hashtable>();
            List<Hashtable> ckevalues = new List<Hashtable>();
            List<Cookie> ckeList = new List<Cookie>();
            if (initCookies != null)
            {
                for (int i = 0; i < initCookies.Count; i++)
                {
                    ckeList.Add(initCookies[i]);
                    Hashtable h = new Hashtable();
                    h.Add(initCookies[i].Name, initCookies[i].Value);
                    ckevalues.Add(h);
                }
            }
            try
            {

                List<string> rckes = new List<string>();
                for (int i = 0; i < cooks.Count; i++)
                {
                    rckes.Add(cooks[i].Name);
                }
                foreach (string set in setCookie)
                {
                    Cookie cke = new Cookie();
                    for (int i = 0; i < set.Split(';').ToList().Count; i++)
                    {
                        List<string> v = new List<string>();
                        string item = set.Split(';').ToList()[i];
                        for (int ii = 1; ii < item.Split('=').ToList().Count; ii++)
                        {
                            v.Add(item.Split('=')[ii]);
                        }
                        string va = String.Join('='.ToString(), v);
                        string key = new Regex(@"^(\s*)").Replace(item.Split('=').ToList()[0], "");
                        string value = new Regex(@"^(\s*)").Replace(va, "");
                        if (i == 0)
                        {
                            cke.Name = key;
                            cke.Value = value;
                        }
                        else
                        {
                            switch (key.ToLower())
                            {
                                case "comment":
                                    cke.Comment = value;
                                    break;
                                case "commenturi":
                                    cke.CommentUri = new Uri(value);
                                    break;
                                case "httponly":
                                    cke.HttpOnly = bool.Parse(value);
                                    break;
                                case "discard":
                                    cke.Discard = bool.Parse(value);
                                    break;
                                case "domain":
                                    cke.Domain = value;
                                    break;
                                case "expires":
                                    cke.Expires = DateTime.Parse(value);
                                    break;
                                case "path":
                                    cke.Path = value;
                                    break;
                                case "port":
                                    cke.Port = value;
                                    break;
                                case "secure":
                                    cke.Secure = bool.Parse(value);
                                    break;
                                case "version":
                                    cke.Version = int.Parse(value);
                                    break;
                            }
                        }
                        if (!rckes.Contains(cke.Name))
                        {
                            cooks.Add(cke);
                        }
                        else
                        {
                            CookieCollection tempRCkes = new CookieCollection();
                            for (int ii = 0; ii < cooks.Count; ii++)
                            {
                                Cookie current = cooks[ii];
                                if (!current.Name.Equals(cke.Name))
                                {
                                    tempRCkes.Add(current);
                                }
                            }
                            tempRCkes.Add(cke);
                            cooks = new CookieCollection();
                            for (int ii = 0; ii < tempRCkes.Count; ii++)
                            {
                                cooks.Add(tempRCkes[ii]);
                            }
                            rckes = new List<string>();
                            for (int ii = 0; ii < cooks.Count; ii++)
                            {
                                rckes.Add(cooks[ii].Name);
                            }
                        }
                    }
                }
                if (cooks != null)
                {
                    for (int i = 0; i < cooks.Count; i++)
                    {
                        Hashtable h = new Hashtable();
                        h.Add(cooks[i].Name, cooks[i].Value);
                        rckevalues.Add(h);
                    }
                }
                if (ckevalues != null)
                {
                    if (rckevalues.Count > 0)
                    {
                        List<string> rNames = new List<string>();
                        List<string> rValue = new List<string>();
                        for (int i = 0; i < rckevalues.Count; i++)
                        {
                            string rcken = rckevalues[i].Keys.ToString();
                            string rckev = rckevalues[i].Values.ToString();
                            rNames.Add(rcken);
                            rValue.Add(rckev);
                        }
                        for (int i = 0; i < ckevalues.Count; i++)
                        {
                            string ckeName = ckevalues[i].Keys.ToString();
                            string ckeValu = ckevalues[i].Values.ToString();
                            if (!rValue.Contains(ckeValu))
                            {
                                if (!rNames.Contains(ckeName))
                                {
                                    cooks.Add(ckeList.Where(item => item.Name.Equals(ckeName)).FirstOrDefault());
                                }
                            }
                            else
                            {
                                if (!rNames.Contains(ckeName))
                                {
                                    cooks.Add(ckeList.Where(item => item.Name.Equals(ckeName)).FirstOrDefault());
                                }
                            }
                        }
                    }
                    else
                    {
                        ckeList.ForEach(i => cooks.Add(i));
                    }
                }
            }
            catch (Exception e)
            {
                ex.Add(e);
            }
            return cooks;
        }
        public static void CopyTo(Stream src, Stream dest)
        {
            byte[] bytes = new byte[4096];
            int cnt;
            while ((cnt = src.Read(bytes, 0, bytes.Length)) != 0)
            {
                dest.Write(bytes, 0, cnt);
            }
        }
        public static string Unzip(byte[] bytes)
        {
            using (var msi = new MemoryStream(bytes))
            using (var mso = new MemoryStream())
            {
                using (var gs = new GZipStream(msi, CompressionMode.Decompress))
                {
                    //gs.CopyTo(mso);
                    CopyTo(gs, mso);
                }
                return Encoding.UTF8.GetString(mso.ToArray());
            }
        }
        public static async Task<RetObject> SendHttp(string uri = null, HttpMethod method = null, OrderedDictionary headers = null, CookieCollection cookies = null, string contentType = null, string body = null, string filepath = null)
        {
            byte[] reStream;
            RetObject retObj = new RetObject();
            HttpResponseMessage res = new HttpResponseMessage();
            OrderedDictionary httpResponseHeaders = new OrderedDictionary();
            CookieCollection responseCookies;
            CookieCollection rCookies = new CookieCollection();
            List<string> setCookieValue = new List<string>();
            CookieContainer coo = new CookieContainer();
            dynamic dom = new object();
            string htmlString = String.Empty;
            if (method == null)
            {
                method = HttpMethod.Get;
            }
            HttpClientHandler handle = new HttpClientHandler()
            {
                AutomaticDecompression = (DecompressionMethods)1 & (DecompressionMethods)2,
                UseProxy = false,
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = Int32.MaxValue,
                MaxConnectionsPerServer = Int32.MaxValue,
                MaxResponseHeadersLength = Int32.MaxValue,
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12
            };
            HttpClient client = new HttpClient(handle);
            if (!client.DefaultRequestHeaders.Contains("User-Agent"))
            {
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36");
            }
            client.DefaultRequestHeaders.Add("Path", (new Uri(uri).PathAndQuery));
            List<string> headersToSkip = new List<string>();
            headersToSkip.Add("Accept");
            headersToSkip.Add("pragma");
            headersToSkip.Add("Cache-Control");
            headersToSkip.Add("Date");
            headersToSkip.Add("Content-Length");
            headersToSkip.Add("Content-Type");
            headersToSkip.Add("Expires");
            headersToSkip.Add("Last-Modified");
            if (headers != null)
            {
                headersToSkip.ForEach((i) => {
                    headers.Remove(i);
                });
                IEnumerator enume = headers.Keys.GetEnumerator();
                while (enume.MoveNext())
                {
                    string key = enume.Current.ToString();
                    string value = String.Join("\n", headers[key]);
                    if (client.DefaultRequestHeaders.Contains(key))
                    {
                        client.DefaultRequestHeaders.Remove(key);
                    }
                    try
                    {
                        client.DefaultRequestHeaders.Add(key, value);
                    }
                    catch
                    {
                        client.DefaultRequestHeaders.TryAddWithoutValidation(key, value);
                    }
                }
            }
            if (cookies != null)
            {
                IEnumerator cnume = cookies.GetEnumerator();
                while (cnume.MoveNext())
                {
                    Cookie cook = (Cookie)cnume.Current;
                    coo.Add(cook);
                }
                handle.CookieContainer = coo;
            }
            bool except = false;
            switch (method.ToString())
            {
                case "DELETE":
                    res = await client.SendAsync((new HttpRequestMessage(method, uri)));
                    if (res.Content.Headers.ContentEncoding.ToString().ToLower().Equals("gzip"))
                    {
                        reStream = res.Content.ReadAsByteArrayAsync().Result;
                        htmlString = Unzip(reStream);
                    }
                    else
                    {
                        htmlString = res.Content.ReadAsStringAsync().Result;
                    }
                    try
                    {
                        setCookieValue = res.Headers.GetValues("Set-Cookie").ToList();
                    }
                    catch
                    { }
                    res.Headers.ToList().ForEach((i) =>
                    {
                        httpResponseHeaders.Add(i.Key, i.Value);
                    });
                    res.Content.Headers.ToList().ForEach((i) =>
                    {
                        httpResponseHeaders.Add(i.Key, i.Value);
                    });
                    responseCookies = handle.CookieContainer.GetCookies(new Uri(uri));
                    rCookies = SetCookieParser(setCookieValue, responseCookies, cookies);
                    if (!String.IsNullOrEmpty(htmlString))
                    {
                        dom = DOMParser(htmlString);
                        retObj.HtmlDocument = dom;
                    }
                    retObj.HttpResponseHeaders = httpResponseHeaders;
                    retObj.HttpResponseMessage = res;
                    break;
                case "GET":
                    res = await client.SendAsync((new HttpRequestMessage(method, uri)));
                    if (res.Content.Headers.ContentEncoding.ToString().ToLower().Equals("gzip"))
                    {
                        reStream = res.Content.ReadAsByteArrayAsync().Result;
                        htmlString = Unzip(reStream);
                    }
                    else
                    {
                        try
                        {
                            htmlString = res.Content.ReadAsStringAsync().Result;
                        }
                        catch
                        {
                            except = true;
                        }
                        if (except)
                        {
                            var responseStream = await res.Content.ReadAsStreamAsync().ConfigureAwait(false);
                            using (var sr = new StreamReader(responseStream, Encoding.UTF8))
                            {
                                htmlString = await sr.ReadToEndAsync().ConfigureAwait(false);
                            }
                        }

                    }
                    try
                    {
                        setCookieValue = res.Headers.GetValues("Set-Cookie").ToList();
                    }
                    catch
                    { }
                    res.Headers.ToList().ForEach((i) =>
                    {
                        httpResponseHeaders.Add(i.Key, i.Value);
                    });
                    res.Content.Headers.ToList().ForEach((i) =>
                    {
                        httpResponseHeaders.Add(i.Key, i.Value);
                    });
                    responseCookies = handle.CookieContainer.GetCookies(new Uri(uri));
                    rCookies = SetCookieParser(setCookieValue, responseCookies, cookies);
                    if (!String.IsNullOrEmpty(htmlString))
                    {
                        dom = DOMParser(htmlString);
                        retObj.HtmlDocument = dom;
                    }
                    retObj.HttpResponseHeaders = httpResponseHeaders;
                    retObj.HttpResponseMessage = res;
                    break;
                case "HEAD":
                    res = await client.SendAsync((new HttpRequestMessage(method, uri)));
                    try
                    {
                        setCookieValue = res.Headers.GetValues("Set-Cookie").ToList();
                    }
                    catch
                    { }
                    res.Headers.ToList().ForEach((i) =>
                    {
                        httpResponseHeaders.Add(i.Key, i.Value);
                    });
                    res.Content.Headers.ToList().ForEach((i) =>
                    {
                        httpResponseHeaders.Add(i.Key, i.Value);
                    });
                    responseCookies = handle.CookieContainer.GetCookies(new Uri(uri));
                    rCookies = SetCookieParser(setCookieValue, responseCookies, cookies);
                    retObj.HttpResponseHeaders = httpResponseHeaders;
                    retObj.HttpResponseMessage = res;
                    break;
                case "OPTIONS":
                    res = await client.SendAsync((new HttpRequestMessage(method, uri)));
                    if (res.Content.Headers.ContentEncoding.ToString().ToLower().Equals("gzip"))
                    {
                        reStream = res.Content.ReadAsByteArrayAsync().Result;
                        htmlString = Unzip(reStream);
                    }
                    else
                    {
                        htmlString = res.Content.ReadAsStringAsync().Result;
                    }
                    try
                    {
                        setCookieValue = res.Headers.GetValues("Set-Cookie").ToList();
                    }
                    catch
                    { }
                    res.Headers.ToList().ForEach((i) =>
                    {
                        httpResponseHeaders.Add(i.Key, i.Value);
                    });
                    res.Content.Headers.ToList().ForEach((i) =>
                    {
                        httpResponseHeaders.Add(i.Key, i.Value);
                    });
                    responseCookies = handle.CookieContainer.GetCookies(new Uri(uri));
                    rCookies = SetCookieParser(setCookieValue, responseCookies, cookies);
                    if (!String.IsNullOrEmpty(htmlString))
                    {
                        dom = DOMParser(htmlString);
                        retObj.HtmlDocument = dom;
                    }
                    retObj.HttpResponseHeaders = httpResponseHeaders;
                    retObj.HttpResponseMessage = res;
                    break;
                case "POST":
                    if (String.IsNullOrEmpty(contentType))
                    {
                        contentType = "application/x-www-form-urlencoded";
                    }
                    if (!String.IsNullOrEmpty(body))
                    {
                        switch (contentType)
                        {
                            case @"application/x-www-form-urlencoded":
                                res = await client.SendAsync(
                                    (new HttpRequestMessage(method, uri)
                                    {
                                        Content = (new StringContent(body, Encoding.UTF8, contentType))
                                    })
                                );
                                break;
                            case @"multipart/form-data":
                                MultipartFormDataContent mpc = new MultipartFormDataContent("Boundary----" + DateTime.Now.Ticks.ToString("x"));
                                if (!String.IsNullOrEmpty(filepath))
                                {
                                    if (File.Exists(filepath))
                                    {
                                        ByteArrayContent bac = new ByteArrayContent(File.ReadAllBytes(filepath));
                                        bac.Headers.Add("Content-Type", MimeMapping.GetMimeMapping(filepath));
                                        bac.Headers.ContentDisposition = ContentDispositionHeaderValue.Parse("attachment");
                                        bac.Headers.ContentDisposition.Name = "file";
                                        bac.Headers.ContentDisposition.FileName = new FileInfo(filepath).Name;
                                        mpc.Add(bac, new FileInfo(filepath).Name);
                                    }
                                }
                                if (!String.IsNullOrEmpty(body))
                                {
                                    StringContent sc = new StringContent(body, Encoding.UTF8, @"application/x-www-form-urlencoded");
                                    mpc.Add(sc);
                                }
                                res = await client.SendAsync(
                                    (new HttpRequestMessage(method, uri)
                                    {
                                        Content = mpc
                                    })
                                );
                                break;
                            default:
                                res = await client.SendAsync(
                                    (new HttpRequestMessage(method, uri)
                                    {
                                        Content = (new StringContent(body, Encoding.UTF8, contentType))
                                    })
                                );
                                break;
                        }
                        if (res.Content.Headers.ContentEncoding.ToString().ToLower().Equals("gzip"))
                        {
                            reStream = res.Content.ReadAsByteArrayAsync().Result;
                            htmlString = Unzip(reStream);
                        }
                        else
                        {
                            htmlString = res.Content.ReadAsStringAsync().Result;
                        }
                        try
                        {
                            setCookieValue = res.Headers.GetValues("Set-Cookie").ToList();
                        }
                        catch
                        { }
                        res.Headers.ToList().ForEach((i) =>
                        {
                            httpResponseHeaders.Add(i.Key, i.Value);
                        });
                        res.Content.Headers.ToList().ForEach((i) =>
                        {
                            httpResponseHeaders.Add(i.Key, i.Value);
                        });
                    }
                    else
                    {
                        switch (contentType)
                        {
                            case @"application/x-www-form-urlencoded":
                                res = await client.SendAsync(
                                    (new HttpRequestMessage(method, uri)
                                    {
                                        Content = (new StringContent(String.Empty, Encoding.UTF8, contentType))
                                    })
                                );
                                break;
                            case @"multipart/form-data":
                                MultipartFormDataContent mpc = new MultipartFormDataContent("Boundary----" + DateTime.Now.Ticks.ToString("x"));
                                if (!String.IsNullOrEmpty(filepath))
                                {
                                    if (File.Exists(filepath))
                                    {
                                        ByteArrayContent bac = new ByteArrayContent(File.ReadAllBytes(filepath));
                                        bac.Headers.Add("Content-Type", MimeMapping.GetMimeMapping(filepath));
                                        bac.Headers.ContentDisposition = ContentDispositionHeaderValue.Parse("attachment");
                                        bac.Headers.ContentDisposition.Name = "file";
                                        bac.Headers.ContentDisposition.FileName = new FileInfo(filepath).Name;
                                        mpc.Add(bac, new FileInfo(filepath).Name);
                                    }
                                }
                                res = await client.SendAsync(
                                    (new HttpRequestMessage(method, uri)
                                    {
                                        Content = mpc
                                    })
                                );
                                break;
                            default:
                                res = await client.SendAsync((new HttpRequestMessage(method, uri)));
                                break;
                        }
                        if (res.Content.Headers.ContentEncoding.ToString().ToLower().Equals("gzip"))
                        {
                            reStream = res.Content.ReadAsByteArrayAsync().Result;
                            htmlString = Unzip(reStream);
                        }
                        else
                        {
                            htmlString = res.Content.ReadAsStringAsync().Result;
                        }
                        try
                        {
                            setCookieValue = res.Headers.GetValues("Set-Cookie").ToList();
                        }
                        catch
                        { }
                        res.Headers.ToList().ForEach((i) =>
                        {
                            httpResponseHeaders.Add(i.Key, i.Value);
                        });
                        res.Content.Headers.ToList().ForEach((i) =>
                        {
                            httpResponseHeaders.Add(i.Key, i.Value);
                        });
                    }
                    responseCookies = handle.CookieContainer.GetCookies(new Uri(uri));
                    rCookies = SetCookieParser(setCookieValue, responseCookies, cookies);
                    if (!String.IsNullOrEmpty(htmlString))
                    {
                        dom = DOMParser(htmlString);
                        retObj.HtmlDocument = dom;
                    }
                    retObj.HttpResponseHeaders = httpResponseHeaders;
                    retObj.HttpResponseMessage = res;
                    break;
                case "PUT":
                    if (String.IsNullOrEmpty(contentType))
                    {
                        contentType = "application/x-www-form-urlencoded";
                    }
                    if (!String.IsNullOrEmpty(body))
                    {
                        res = await client.SendAsync(
                            (new HttpRequestMessage(method, uri)
                            {
                                Content = (new StringContent(body, Encoding.UTF8, contentType))
                            })
                        );
                        if (res.Content.Headers.ContentEncoding.ToString().ToLower().Equals("gzip"))
                        {
                            reStream = res.Content.ReadAsByteArrayAsync().Result;
                            htmlString = Unzip(reStream);
                        }
                        else
                        {
                            htmlString = res.Content.ReadAsStringAsync().Result;
                        }
                        try
                        {
                            setCookieValue = res.Headers.GetValues("Set-Cookie").ToList();
                        }
                        catch
                        { }
                        res.Headers.ToList().ForEach((i) =>
                        {
                            httpResponseHeaders.Add(i.Key, i.Value);
                        });
                        res.Content.Headers.ToList().ForEach((i) =>
                        {
                            httpResponseHeaders.Add(i.Key, i.Value);
                        });
                    }
                    else
                    {
                        res = await client.SendAsync((new HttpRequestMessage(method, uri)));
                        if (res.Content.Headers.ContentEncoding.ToString().ToLower().Equals("gzip"))
                        {
                            reStream = res.Content.ReadAsByteArrayAsync().Result;
                            htmlString = Unzip(reStream);
                        }
                        else
                        {
                            htmlString = res.Content.ReadAsStringAsync().Result;
                        }
                        try
                        {
                            setCookieValue = res.Headers.GetValues("Set-Cookie").ToList();
                        }
                        catch
                        { }
                        res.Headers.ToList().ForEach((i) =>
                        {
                            httpResponseHeaders.Add(i.Key, i.Value);
                        });
                        res.Content.Headers.ToList().ForEach((i) =>
                        {
                            httpResponseHeaders.Add(i.Key, i.Value);
                        });
                    }
                    responseCookies = handle.CookieContainer.GetCookies(new Uri(uri));
                    rCookies = SetCookieParser(setCookieValue, responseCookies, cookies);
                    if (!String.IsNullOrEmpty(htmlString))
                    {
                        dom = DOMParser(htmlString);
                        retObj.HtmlDocument = dom;
                    }
                    retObj.HtmlDocument = dom;
                    retObj.HttpResponseHeaders = httpResponseHeaders;
                    retObj.HttpResponseMessage = res;
                    break;
                case "TRACE":
                    res = await client.SendAsync((new HttpRequestMessage(method, uri)));
                    if (res.Content.Headers.ContentEncoding.ToString().ToLower().Equals("gzip"))
                    {
                        reStream = res.Content.ReadAsByteArrayAsync().Result;
                        htmlString = Unzip(reStream);
                    }
                    else
                    {
                        htmlString = res.Content.ReadAsStringAsync().Result;
                    }
                    try
                    {
                        setCookieValue = res.Headers.GetValues("Set-Cookie").ToList();
                    }
                    catch
                    { }
                    res.Headers.ToList().ForEach((i) =>
                    {
                        httpResponseHeaders.Add(i.Key, i.Value);
                    });
                    res.Content.Headers.ToList().ForEach((i) =>
                    {
                        httpResponseHeaders.Add(i.Key, i.Value);
                    });
                    responseCookies = handle.CookieContainer.GetCookies(new Uri(uri));
                    rCookies = SetCookieParser(setCookieValue, responseCookies, cookies);
                    if (!String.IsNullOrEmpty(htmlString))
                    {
                        dom = DOMParser(htmlString);
                        retObj.HtmlDocument = dom;
                    }
                    retObj.HttpResponseHeaders = httpResponseHeaders;
                    retObj.HttpResponseMessage = res;
                    break;
            }
            if (!String.IsNullOrEmpty(htmlString))
            {
                retObj.ResponseText = htmlString;
            }
            retObj.CookieCollection = rCookies;
            return retObj;
        }
    }
    public class HttpRequest
    {
        public string uri;
        public HttpMethod method;
        public OrderedDictionary headers;
        public CookieCollection cookies;
        public string contentType;
        public string body;
        public string filePath;
        public static RetObject Send(string uri = null, HttpMethod method = null, OrderedDictionary headers = null, CookieCollection cookies = null, string contentType = null, string body = null, string filepath = null)
        {
            Task<RetObject> r = Utils.SendHttp(uri, method, headers, cookies, contentType, body, filepath);
            return r.Result;
        }
    }
    public class RetObject
    {
        public string ResponseText
        {
            get;
            set;
        }
        public OrderedDictionary HttpResponseHeaders
        {
            get;
            set;
        }
        public CookieCollection CookieCollection
        {
            get;
            set;
        }
        public HTMLDocument HtmlDocument
        {
            get;
            set;
        }
        public HttpResponseMessage HttpResponseMessage
        {
            get;
            set;
        }
    }
}
namespace nslist
{
    using System;
    using System.Collections.Generic;
    using System.Text.RegularExpressions;
    using System.Net.Http;
    public class nsitem
    {
        public nsitem(Regex Endpoint, HttpMethod Method)
        {
            this.endpoint = Endpoint;
            this.method = Method;
        }
        public Regex endpoint { get; set; }
        public HttpMethod method { get; set; }
    }
    public class nslist
    {
        public static List<nsitem> NameSpaceList = new List<nsitem>()
        {
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/application/rate_limit_status.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/favorites/list.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/followers/ids.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/followers/list.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/friends/ids.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/friends/list.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/friendships/show.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/help/configuration.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/help/languages.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/lists/list.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/lists/members/show.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/lists/members.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/lists/memberships.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/lists/ownerships.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/lists/show.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/lists/statuses.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/lists/subscribers/show.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/lists/subscribers.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/lists/subscriptions.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/search/tweets.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/statuses/lookup.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/statuses/retweeters/ids.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/statuses/retweets/\d+.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/statuses/show.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/statuses/user_timeline.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/trends/available.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/trends/closest.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/trends/place.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/users/lookup.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/users/show.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/timeline/media/\d+.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/tweets$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/tweets/\d+$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/tweets/search/recent$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/users$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/users/\d+$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/users/\d+/followers$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/users/\d+/following$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/users/\d+/mentions$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/users/\d+/tweets$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/users/by$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/users/by/username/.+$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/account/settings.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/blocks/ids.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/blocks/list.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/collections/entries.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/collections/list.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/collections/show.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/friendships/incoming.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/friendships/outgoing.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/geo/id/.+.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/geo/reverse_geocode.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/geo/search.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/mutes/users/ids.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/mutes/users/list.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/statuses/home_timeline.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/statuses/mentions_timeline.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/users/profile_banner.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/users/search.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://publish.twitter.com/oembed$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/2/timeline/conversation/\d+.json$"),HttpMethod.Get),
            new nsitem(new Regex(@"^https://api.twitter.com/1.1/friends/following/list.json$"),HttpMethod.Get)
        };
    }
}