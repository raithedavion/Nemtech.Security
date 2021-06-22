using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using System.Net;
using System.Collections.Specialized;
using System.Web;
using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.AspNetCore.WebUtilities;
using System.IO;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc.WebApiCompatShim;

namespace Nemtech.Authentication.Hmac
{
    public class HmacHandler : AuthenticationHandler<HmacOptions>
    {
        //private properties for this authentication method.
        private static string Signature;
        private static string Nonce;
        private static Encoding Encoder { get { return Encoding.UTF8; } set { } }
        /// <summary>
        /// Memory Cache to use
        /// </summary>
        public IMemoryCache MemoryCache { get; set; }

        /// <summary>
        /// Constructor when caching is disabled
        /// </summary>
        /// <param name="options"></param>
        /// <param name="logger"></param>
        /// <param name="encoder"></param>
        /// <param name="dataProtection"></param>
        /// <param name="clock"></param>
        public HmacHandler(IOptionsMonitor<HmacOptions> options, ILoggerFactory logger, UrlEncoder encoder, IDataProtectionProvider dataProtection, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        /// <summary>
        /// Constructor for when caching is enabled
        /// </summary>
        /// <param name="options"></param>
        /// <param name="logger"></param>
        /// <param name="encoder"></param>
        /// <param name="dataProtection"></param>
        /// <param name="clock"></param>
        /// <param name="cache"></param>
        public HmacHandler(IOptionsMonitor<HmacOptions> options, ILoggerFactory logger, UrlEncoder encoder, IDataProtectionProvider dataProtection, ISystemClock clock, IMemoryCache cache)
            : base(options, logger, encoder, clock)
        {
            MemoryCache = cache;
        }

        /// <summary>
        /// Handle the authentication request
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            //If Authorization header is missing, fail immediately.
            string authorization = Request.Headers["Authorization"];
            if (string.IsNullOrEmpty(authorization))
                return AuthenticateResult.Fail("Authorization Header Missing");
            string AccessAndSignature = string.Empty;

            //Check if AuthName if it is, check to ensure the Authorization header contains it, if it does get the accessid/signature portion
            if (!string.IsNullOrEmpty(Options.AuthName))
                if (authorization.StartsWith(Options.AuthName, StringComparison.OrdinalIgnoreCase))
                    AccessAndSignature = authorization.Substring(Options.AuthName.Length).Trim();
                else
                    return AuthenticateResult.Fail("Authentication header missing signature name.");
            else
                AccessAndSignature = authorization;

            //split the authorization header format
            //AccessAndSignature = AccessAndSignature.Replace("HMAC-SHA256 ", "");
            string[] authValues = AccessAndSignature.Split(',');
            string Credential = authValues[0].Replace("Credential=", "");
            string SignedHeaders = authValues[1].Replace("SignedHeaders=", "").Trim();
            Signature = authValues[2].Replace("Signature=", string.Empty).Trim();
            if (Options.EnableNonce)
                Nonce = authValues[3];

            if (Options.EnableDeviceOS)
            {
                Options.UserAgent = Request.Headers["User-Agent"];
            }

            string[] credentialArray = Credential.Split('/');

            if (credentialArray.Length != 5)
                return AuthenticateResult.Fail("Credential is not expected length");

            //Set the AppID/PublicKey/etc
            Options.AccessID = credentialArray[0];
            string _dateStamp = credentialArray[1];
            string _OS = credentialArray[2];
            string _Service = credentialArray[3];

            //Set the request timestamp.  If it isn't there, auth fails.
            string timeStamp = Request.Headers["Date"];
            if (string.IsNullOrEmpty(timeStamp))
                return AuthenticateResult.Fail("Missing Date header.");

            //check to see if the request timestamp is out of the bounds of an acceptable request time
            if (!CheckDateHeader(timeStamp))
                return AuthenticateResult.Fail("Request has expired.");

            //If nonce is enabled, check to see if the nonce has been used already (uses same timeout structure as the timestamp
            if (Options.EnableNonce)
                if (!CheckNonce())
                    return AuthenticateResult.Fail("Not a valid request.");
            
            string SentSignature = ConstructStringToSign(Request, SignedHeaders, _Service, _OS);
            
            //Attempt to validate the request by comparing a server side hash to the passed in hash
            if (isValid(Signature, SentSignature, _dateStamp, _Service, _OS))
            {
                //If signatures match, then authorize the request and create a "ticket" for this request.
                HmacIdentity identityUser = null;
                if (identityUser == null)
                {
                    identityUser = new HmacIdentity(Options.AccessID);
                }
                var principal = new ClaimsPrincipal(identityUser);
                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), HmacDefaults.AuthenticationScheme);
                return AuthenticateResult.Success(ticket);
            }

            //Default Fail.
            return AuthenticateResult.Fail("Signature not valid.");
        }

        private AuthenticationTicket GetTicket()
        {
            HmacIdentity identityUser = null;
            if (identityUser == null)
            {
                identityUser = new HmacIdentity("blah");
            }
            var principal = new ClaimsPrincipal(identityUser);
            var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), HmacDefaults.AuthenticationScheme);
            return ticket;
        }

        /// <summary>
        /// Check the timestamp to see if it is within a given range
        /// </summary>
        /// <param name="timeStamp"></param>
        /// <returns></returns>
        private bool CheckDateHeader(string timeStamp)
        {
            DateTime Now = DateTime.UtcNow;
            DateTime RequestDate = DateTime.Parse(timeStamp).ToUniversalTime();
            if (RequestDate < Now.AddMinutes(-Options.RequestTimeLimit))
                return false;
            if (RequestDate > Now.AddMinutes(Options.RequestTimeLimit))
                return false;
            return true;
        }

        /// <summary>
        /// Determine if nonce has been used before or not
        /// </summary>
        /// <returns></returns>
        private bool CheckNonce()
        {
            object temp = MemoryCache.Get(Nonce);
            if (temp != null)
                return false;
            MemoryCache.Set("Nonce", Nonce, DateTime.Now.AddMinutes(Options.RequestTimeLimit));
            return true;
        }

        private string ConstructStringToSign(HttpRequest context, string signedHeaders, string service, string os)
        {
            
            string dirAppDate = context.Headers["x-dirapp-date"];
            string dateScope = dirAppDate.Split('T')[0];
            string canonicalUri = context.Path;
            string canonicalQueryString = context.QueryString.Value;
            string canonicalHeaders = string.Empty;
            foreach (string header in signedHeaders.Split(';'))
            {
                string value = GetHeader(context, header);
                canonicalHeaders += string.Format("{0}:{1}\n", header, value);
            }
            string payload = GetRequestBody(context);
            string payloadHash = sha256(payload);
            string canonicalRequest = string.Format("{0}\n{1}\n{2}\n{3}\n{4}\n{5}", context.Method, canonicalUri, canonicalQueryString, canonicalHeaders.Trim(),
                signedHeaders.Trim(), payloadHash);
            string algorithm = "HMAC-SHA256";
            string credential_scope = string.Format("{0}/{1}/{2}/{3}", dateScope, os, service, "dirapp_request");
            return string.Format("{0}\n{1}\n{2}\n{3}", algorithm, dirAppDate, credential_scope, sha256(canonicalRequest));
        }


        private string GetHeader(HttpRequest context, string key)
        {
            var Headers = context.Headers.ToList();
            foreach(var header in Headers)
            {
                string temp = header.Key.ToLower();
                if (temp == key)
                    return header.Value;
            }
            return string.Empty;
        }

        private string GetRequestBody(HttpRequest req)
        {
            string body = string.Empty;
            try
            {
                using (var reader = new StreamReader(req.Body))
                {
                    body = reader.ReadToEndAsync().Result;
                    byte[] requestData = Encoding.UTF8.GetBytes(body);
                    Request.Body = new MemoryStream(requestData);
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return body;
        }

        public bool isValid(string hash, string toHash, string date, string service, string os)
        {
            try
            {
                //Lookup private key here.
                string Key = Options.PrivateKey;
                byte[] keyBytes = GetSignatureKey(Key, date, service, os);
                string LocalHash = GetSignature(toHash, keyBytes);
                return hash == LocalHash;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Hash the signature using specified cipher strength.  Default is HMACSHA1
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public string Hash(string plainText, string privateKey)
        {
            int cipherStrength = Convert.ToInt32(Options.CipherStrength);
            try
            {
                byte[] KeyBytes = Encoder.GetBytes(privateKey);
                HMAC Cipher = null;
                if (cipherStrength == 256)
                    Cipher = new HMACSHA256(KeyBytes);
                else if (cipherStrength == 384)
                    Cipher = new HMACSHA384(KeyBytes);
                else if (cipherStrength == 512)
                    Cipher = new HMACSHA512(KeyBytes);
                else
                    //Default
                    Cipher = new HMACSHA256(KeyBytes);
                byte[] PlainBytes = Encoder.GetBytes(plainText);
                byte[] HashedBytes = Cipher.ComputeHash(PlainBytes);
                return WebEncoders.Base64UrlEncode(HashedBytes);//Convert.ToBase64String(HashedBytes);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public string GetSignature(string plainText, byte[] privateKey)
        {
            int cipherStrength = 256;
            try
            {
                byte[] KeyBytes = privateKey;
                HMAC Cipher = null;
                if (cipherStrength == 256)
                    Cipher = new HMACSHA256(KeyBytes);
                else if (cipherStrength == 384)
                    Cipher = new HMACSHA384(KeyBytes);
                else if (cipherStrength == 512)
                    Cipher = new HMACSHA512(KeyBytes);
                else
                    //Default
                    Cipher = new HMACSHA256(KeyBytes);
                byte[] PlainBytes = Encoder.GetBytes(plainText);
                byte[] HashedBytes = Cipher.ComputeHash(PlainBytes);
                return WebEncoders.Base64UrlEncode(HashedBytes);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Hash the signature using specified cipher strength.  Default is HMACSHA1
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public byte[] Hash(string plainText, byte[] privateKey)
        {
            int cipherStrength = Convert.ToInt32(Options.CipherStrength);
            try
            {
                HMAC Cipher = null;
                if (cipherStrength == 256)
                    Cipher = new HMACSHA256(privateKey);
                else if (cipherStrength == 384)
                    Cipher = new HMACSHA384(privateKey);
                else if (cipherStrength == 512)
                    Cipher = new HMACSHA512(privateKey);
                else
                    //Default
                    Cipher = new HMACSHA256(privateKey);
                byte[] PlainBytes = Encoder.GetBytes(plainText);
                byte[] HashedBytes = Cipher.ComputeHash(PlainBytes);
                return HashedBytes;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private byte[] GetSignatureKey(string key, string dateStamp, string service, string deviceOS = null)
        {
            byte[] kSigning = null;
            string SecretName = Options.AuthName + key;
            byte[] kSecret = Encoding.UTF8.GetBytes(SecretName.ToCharArray());
            //byte[] kSecret = Encoding.UTF8.GetBytes((Options.AuthName + key).ToCharArray());
            string temp = WebEncoders.Base64UrlEncode(kSecret);
            byte[] kDate = Hash(dateStamp, kSecret);
            byte[] kService = Hash(service, kDate);
            if (!string.IsNullOrEmpty(deviceOS))
            {
                byte[] kOS = Hash(deviceOS, kService);
                kSigning = Hash("auth_request", kOS);
            }
            else
                kSigning = Hash("auth_request", kService);
            return kSigning;
        }

        private string sha256(string value)
        {
            StringBuilder Sb = new StringBuilder();

            using (var hash = SHA256.Create())
            {
                Encoding enc = Encoding.UTF8;
                Byte[] result = hash.ComputeHash(enc.GetBytes(value));

                foreach (Byte b in result)
                    Sb.Append(b.ToString("x2"));
            }

            return Sb.ToString();
        }
    }
}
