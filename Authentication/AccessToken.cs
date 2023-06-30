using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.Data;
using System.Data.SqlClient;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Collections.Generic;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace Authentication
{
    public class AccessToken
    {


        public string GetAccessToken()
        {
             
            var foundationUrl = "https://gateway.altusplatform.com/ASMO/4.0/api/Portfolios";
            var foundationEndpoint = "Portfolios";

              string certPath = "C:\\Argus_certificate\\API_keystore.pkcs12";
              string certPwd = "123456";
              string certEmail = "cre_bidev@realpage.com";
              string clientId = "g33rv6Qg6eEYAuLXsMnQuXSLnb8a";
              string clientSecret = "qdZmmX2YQefgf7VQd2roU9gS974a";
              string jwtGenerated = GenerateJwtToken(certEmail, certPath, certPwd);
              string accessToken = GetM2MAccessToken(jwtGenerated, clientId, clientSecret);
              string AuthorizationTkn = "Bearer " + accessToken;

            return AuthorizationTkn;
        }


        public string GenerateJwtToken(string userEmailId, string cPath, string cPwd)
        {
            // Get the Public/Private Key Certificate. This example uses a certificate file stored in an accessible path.
            //  However your program may choose to read from an alternative source like a certificate store.

            var cert = this.GetCertificateFromFile(cPath, cPwd);

            RSA keys = null;
            string thumbPrint = null;

            GetPrivateKeyFromCertificate(cert, out keys, out thumbPrint);

            var securityKey = new RsaSecurityKey(keys);
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256Signature);

            var now = DateTime.UtcNow;
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userEmailId), // Add the email of the Platform User on behalf of which we are requesting platform access
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // Unique identifier for the token. Must be different every time.
            };

            var jwt = new JwtSecurityToken(
                                    "JWTIDP",
                                    "https://core-ids.prod.altusplatform.com/oauth2/token", // OAuth endpoint the token will be sent to
                                    claims,
                                    expires: now.Add(TimeSpan.FromMinutes(60)),
                                    signingCredentials: credentials);

            jwt.Header.Add("kid", cert.Thumbprint.ToLowerInvariant()); // The KID of the certificate. This value is case-sensitive and must be lower-case.
            jwt.Header["alg"] = "RS256";
            jwt.Payload.Add(JwtRegisteredClaimNames.Iat, CalcTokenExpiry(2));

            var handler = new JwtSecurityTokenHandler();

            // Convert Token to String so you can use it in your client
            var tokenString = handler.WriteToken(jwt);
            return tokenString;
            //Console.WriteLine(tokenString);
        }

        public X509Certificate2 GetCertificateFromFile(string filePath, string password)
        {
            // Ensure that the Certificate is appropriately secured with ACL and only accessible by the account under which the program is executing
           
            var cert = new X509Certificate2(filePath, password);
            return cert;
        }

        private void GetPrivateKeyFromCertificate(X509Certificate2 cert, out RSA RSA, out string thumbPrint)
        {
           
            RSA = cert.GetRSAPrivateKey();
            thumbPrint = cert.Thumbprint;
        }

        private static long CalcTokenExpiry(int tokenExpiry)
        {
            // Ensure the Certificate expiry is per the Open SSL Spec
            var Jan1_1970 = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var nowPlusMins = DateTime.UtcNow.AddMinutes(tokenExpiry);
            var expiry = (nowPlusMins - Jan1_1970).TotalSeconds;
            return (long)expiry;
        }

        public string GetM2MAccessToken(string jwtToken, string cliId, string cliSecret)
        {
            try
            {
                using (var client = new WebClient())
                {
                    var auth = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{cliId}:{cliSecret}"));

                    client.QueryString.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
                    client.QueryString.Add("assertion", jwtToken);

                    client.Headers.Add("Authorization", $"Basic {auth}");
                    client.Headers.Add("Content-Type", "application/x-www-form-urlencoded");

                    var responseFromServer = Encoding.ASCII.GetString(client.UploadValues("https://identity.altusplatform.com/oauth2/token", "POST", client.QueryString));

                    AccessTokenResponse tokenResponse = JsonConvert.DeserializeObject<AccessTokenResponse>(responseFromServer);
                    return tokenResponse.AccessToken;
                }
            }
            catch (WebException wex)
            {
                throw wex;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private static void TLS_Protocol()
        {
            try
            { //try TLS 1.3
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)12288
                                                     | (SecurityProtocolType)3072
                                                     | (SecurityProtocolType)768
                                                     | SecurityProtocolType.Tls;
            }
            catch (NotSupportedException)
            {
                try
                { //try TLS 1.2
                    ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072
                                                         | (SecurityProtocolType)768
                                                         | SecurityProtocolType.Tls;
                }
                catch (NotSupportedException)
                {
                    try
                    { //try TLS 1.1
                        ServicePointManager.SecurityProtocol = (SecurityProtocolType)768
                                                             | SecurityProtocolType.Tls;
                    }
                    catch (NotSupportedException)
                    { //TLS 1.0
                        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
                    }
                }
            }
        }

    }
}
