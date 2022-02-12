using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;

namespace SITConnect200600M.Services
{
    public class reCAPTCHAv3
    {
        private readonly IConfiguration _configuration;

        public reCAPTCHAv3(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public virtual async Task<reCaptchaResponse> TokenVerify(string token)
        {
            reCaptchaData data = new reCaptchaData
            {
                Response = token,
                Secret = _configuration["reCaptchaKeyServerSide"]
            };

            HttpClient client = new HttpClient();

            var response = await client.GetStringAsync(
                $"https://www.google.com/recaptcha/api/siteverify?secret={data.Secret}&response={data.Response}");

            
            var serverResponse = JsonConvert.DeserializeObject<reCaptchaResponse>(response);
            
            Console.WriteLine(serverResponse.Score);
            Console.WriteLine(serverResponse.TimeStamp);
            Console.WriteLine(serverResponse.HostName);
            Console.WriteLine(serverResponse.Action);
            
            return serverResponse;
        }
    }


    [Serializable]
    public class reCaptchaResponse
    {
        [JsonProperty("success")]
        public bool IsSuccess { get; set; }
        
        [JsonProperty("challenge_ts")]
        public DateTime TimeStamp { get; set; }
        
        [JsonProperty("hostname")]
        public string HostName { get; set; }

        [JsonProperty("score")] public double Score { get; set; } = 0;
        
        [JsonProperty("action")]
        public string Action { get; set; }
    }

    public class reCaptchaData
    {
        public string Response { get; set; }
        public string Secret { get; set; }
    }
}