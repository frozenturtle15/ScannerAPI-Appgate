using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace ScannerAPI
{
    public class MVCConnection
    {
        public iam_tokenClass iam_token = new iam_tokenClass();
        public mvc_authinfoClass mvc_authinfo = new mvc_authinfoClass();
        public class iam_tokenClass
        {
            public string token_type;
            public DateTime expires_at;
            public string access_token;

        }

        public class mvc_authinfoClass
        {
            public string token_type;
            public string access_token;
            public string refresh_token;
            public string tenant_ID;
            public string tenant_Name;
            public string userID;
            public string email;
            public string users;
            public DateTime expires_at;
        }
        public bool isAuthenticated()
        {
            if (string.IsNullOrEmpty(iam_token.access_token) || DateTime.Now > iam_token.expires_at)
            {
                return false;
            }
            else
            {
                return true;
            }

        }
        public async Task<bool> AuthenticateAsync(string username, string password, string bpsTenantid, string env, ILogger log)
        {
            string iam_url = "https://iam.mcafee-cloud.com/iam/v1.1/token";  //hard coded

            if (string.IsNullOrEmpty(env)) { env = "www.myshn.net"; }


            var iam_payload = new Dictionary<string, string>
                    {
                        { "client_id", "0oae8q9q2y0IZOYUm0h7" },
                        { "grant_type", "password" },
                        { "username", username },
                        { "password", password },
                        { "scope", "shn.con.r web.adm.x web.rpt.x web.rpt.r web.lst.x web.plc.x web.xprt.x web.cnf.x uam:admin" },
                        { "tenant_id", bpsTenantid },
                    };

            try  //Authenticate to McAfee IAM
            {
                HttpClient client = new HttpClient();
                var iam_data = new FormUrlEncodedContent(iam_payload);
                var iam_response = await client.PostAsync(iam_url, iam_data);

                if (iam_response.StatusCode != HttpStatusCode.OK)
                {
                    //Got something other than OK, error out
                    log.LogInformation("Unsuccessful authentication of " + username + "to McAfee IAM.  HTTP Status: " + iam_response.StatusCode.ToString());
                    return false;

                }
                else
                {
                    var iam_responseString = await iam_response.Content.ReadAsStringAsync();
                    var iam_responseData = JsonConvert.DeserializeObject<Dictionary<string, string>>(iam_responseString);

                    iam_token.access_token = iam_responseData["access_token"];
                    iam_token.expires_at = DateTime.Now.AddSeconds(int.Parse(iam_responseData["expires_in"]));
                    iam_token.token_type = iam_responseData["token_type"];

                    //TODO write token information to class
                    log.LogInformation("Successful authentication of " + username + "to McAfee IAM and fetch of iam_token");

                }
            }
            catch (Exception e)
            {
                log.LogInformation("Exception in IAM authentication: " + e.Message);
                return false;
            }

            string mvc_url = "https://" + env + "/neo/neo-auth-service/oauth/token?grant_type=iam_token";
            try //Authenticate to MVISION Cloud
            {
                HttpClient mvc_client = new HttpClient();

                var mvc_request = new HttpRequestMessage()
                {
                    RequestUri = new Uri(mvc_url),
                    Method = HttpMethod.Post
                };
                mvc_request.Headers.Add("x-iam-token", iam_token.access_token);

                var mvc_response = await mvc_client.SendAsync(mvc_request);

                if (mvc_response.StatusCode != HttpStatusCode.OK)
                {
                    //Got something other than OK, error out
                    log.LogInformation("Unsuccessful authentication of " + username + "to MVISION Cloud.  HTTP Status: " + mvc_response.StatusCode.ToString());
                    return false;
                }
                else
                {
                    var mvc_responseString = await mvc_response.Content.ReadAsStringAsync();
                    var mvc_responseData = JsonConvert.DeserializeObject<Dictionary<string, string>>(mvc_responseString);

                    mvc_authinfo.token_type = mvc_responseData["token_type"];
                    mvc_authinfo.access_token = mvc_responseData["access_token"];
                    mvc_authinfo.refresh_token = mvc_responseData["refresh_token"];
                    mvc_authinfo.tenant_ID = mvc_responseData["tenantID"];
                    mvc_authinfo.tenant_Name = mvc_responseData["tenantName"];
                    mvc_authinfo.userID = mvc_responseData["userId"];
                    mvc_authinfo.email = mvc_responseData["email"];
                    mvc_authinfo.expires_at = DateTime.Now.AddSeconds(int.Parse(mvc_responseData["expires_in"]));

                    log.LogInformation("Successful authentication of " + username + "to MVISION Cloud, got access token.");
                    return true;
                }

            }
            catch (Exception e)
            {
                log.LogInformation("Exception in MVISION Cloud authentication: " + e.Message);
                return false;
            }

        }
    }
}
