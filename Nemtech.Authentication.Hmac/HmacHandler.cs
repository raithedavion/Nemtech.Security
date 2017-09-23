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

            //Split the authorization header format accessid:signature or accessid:nonce:signature
            string[] authValues = AccessAndSignature.Split(':');

            if (Options.EnableNonce && authValues.Length != 3)
                return AuthenticateResult.Fail("Invalid Authorization Signature");
            
            if(!Options.EnableNonce && authValues.Length != 2)
                return AuthenticateResult.Fail("Invalid Authorization Signature");

            //Set the AppID/PublicKey/etc
            Options.AccessID = authValues[0];
            if (Options.EnableNonce)
            {
                Nonce = authValues[1];
                Signature = authValues[2];
            }
            else
                Signature = authValues[1];

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

            //Attempt to validate the request by comparing a server side hash to the passed in hash
            if(isValid(Signature, Options.AccessID, ConstructStringToSign(Request)))
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

        //private string SetTimeStamp()
        //{
        //    string timeStamp = Request.Headers["Date"];
        //    if (!string.IsNullOrEmpty(timeStamp))
        //    {
        //        return timeStamp;
        //    }
        //    return string.Empty;
        //}

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
            MemoryCache.Set(Nonce, Nonce, DateTime.Now.AddMinutes(Options.RequestTimeLimit));
            return true;
        }

        /// <summary>
        /// Construct the string that will be hashed and validated
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private string ConstructStringToSign(HttpRequest context)
        {
            string signature = string.Empty;
            signature += context.Method + "\n";
            if(context.Headers.ContainsKey("ContentMd5"))
                signature += context.Headers[HttpRequestHeader.ContentMd5.ToString()] + "\n";
            if (context.Headers.ContainsKey("ContentType"))
                signature += context.Headers[HttpRequestHeader.ContentType.ToString()] + "\n";
            signature += context.Headers["Date"] + "\n";
            if (Options.EnableNonce)
                signature += Nonce + "\n";
            signature += context.Path + "\n";
            if(context.Method != "GET")
                signature += Request.Body;
            return signature;
        }

        /// <summary>
        /// Check to see if local signature generation matches what has been passed in
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="publicKey"></param>
        /// <param name="toHash"></param>
        /// <returns></returns>
        public bool isValid(string hash, string publicKey, string toHash)
        {
            try
            {
                //Lookup private key here.
                string Key = Options.PrivateKey;
                string LocalHash = Hash(toHash, Key);
                return hash == LocalHash;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        ///// <summary>
        ///// Get the private key
        ///// </summary>
        ///// <param name="publicKey"></param>
        ///// <returns></returns>
        //private string PrivateKeySelect(string publicKey)
        //{
        //    try
        //    {
        //        return Options.PrivateKey;
        //    }
        //    catch (Exception ex)
        //    {
        //        throw ex;
        //    }
        //}

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
                    Cipher = new HMACSHA1(KeyBytes);
                byte[] PlainBytes = Encoder.GetBytes(plainText);
                byte[] HashedBytes = Cipher.ComputeHash(PlainBytes);
                return Convert.ToBase64String(HashedBytes);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
    }
}
