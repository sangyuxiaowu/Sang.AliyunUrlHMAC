using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Sang.AliyunUrlHMAC
{
    public sealed class AliyunUrl
    {
        private readonly string _AccessKeyId;
        private readonly string _AccessKeySecret;
        private readonly string _Host = "";

        public AliyunUrl(string accessKeyId, string accessKeySecret, string host)
        {
            _AccessKeyId = accessKeyId;
            _AccessKeySecret = accessKeySecret;
            _Host = host;
        }

        /// <summary>
        /// 签名请求的URL
        /// </summary>
        /// <param name="parameters">参数，非公共</param>
        /// <param name="method">请求类型</param>
        /// <returns></returns>
        public string SignUrl(Dictionary<string, string> parameters, HttpMethod method, string version = "2017-05-25")
        {
            parameters.Add("Format", "JSON");
            parameters.Add("Version", version);
            parameters.Add("SignatureMethod", "HMAC-SHA1");
            parameters.Add("Timestamp", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            parameters.Add("SignatureVersion", "1.0");
            parameters.Add("SignatureNonce", Guid.NewGuid().ToString());
            parameters.Add("AccessKeyId", _AccessKeyId);

            var canonicalizedQueryString = string.Join("&",
                //parameters.OrderBy(x => x.Key)
                new SortedDictionary<string, string>(parameters, StringComparer.Ordinal)
                .Select(x => PercentEncode(x.Key) + "=" + PercentEncode(x.Value)));
            var stringToSign = method.ToString().ToUpper() + "&%2F&" + PercentEncode(canonicalizedQueryString);
            var keyBytes = Encoding.UTF8.GetBytes(_AccessKeySecret + "&");
            var hmac = new HMACSHA1(keyBytes);
            var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));

            parameters.Add("Signature", Convert.ToBase64String(hashBytes));
            return _Host + "?" + string.Join("&", parameters.Select(x => x.Key + "=" + HttpUtility.UrlEncode(x.Value)));
        }

        private string PercentEncode(string value)
        {
            return UpperCaseUrlEncode(value)
                .Replace("+", "%20")
                .Replace("*", "%2A")
                .Replace("%7E", "~");
        }

        private static string UpperCaseUrlEncode(string s)
        {
            char[] temp = HttpUtility.UrlEncode(s).ToCharArray();
            for (int i = 0; i < temp.Length - 2; i++)
            {
                if (temp[i] == '%')
                {
                    temp[i + 1] = char.ToUpper(temp[i + 1]);
                    temp[i + 2] = char.ToUpper(temp[i + 2]);
                }
            }
            return new string(temp);
        }
    }
}