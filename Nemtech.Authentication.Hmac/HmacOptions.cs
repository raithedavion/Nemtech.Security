using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Text;

namespace Nemtech.Authentication.Hmac
{
    /// <summary>
    /// Configurable Options for this authentication method
    /// </summary>
    public class HmacOptions : AuthenticationSchemeOptions
    {
        private string _privateKey { get; set; }
        private string _publicKey { get; set; }
        private string _authName { get; set; }
        private bool _nonceEnabled { get; set; }

        //Method to call when you need grab the private key from an external source
        public delegate string RetrievePrivateKey(string publicKey);
        public event RetrievePrivateKey GetPrivateKey;

        //Retreive private key
        public string PrivateKey
        {
            set { _privateKey = value;  }
            get
            {
                //single caller scenario.  Set in Startup.cs
                if (!string.IsNullOrEmpty(_privateKey))
                    return _privateKey;
                //If public key hasn't been set yet, throw an error (because we are grabbing it from an external source somewhere)
                if (string.IsNullOrEmpty(_publicKey))
                    throw new Exception("No Public Key");
                //if all checks out, attempt to get the private key
                _privateKey = GetPrivateKey(_publicKey);
                return _privateKey;
            }
        }

        //AccessID or public key.  Identifies the caller/user
        public string AccessID
        {
            set { _publicKey = value; }
            get
            {
                if (!string.IsNullOrEmpty(_publicKey))
                    return _publicKey;
                throw new Exception("Public Key Not Set");
            }
        }

        /// <summary>
        /// 1, 256, 384, 512
        /// </summary>
        public HmacCipherStrength CipherStrength { get; set; }

        /// <summary>
        /// AWS, Nemtech, etc.  IE:  Authorization: aws <accessid>:<signature>
        /// </summary>
        public string AuthName
        {
            get
            {
                if(!string.IsNullOrEmpty(_authName))
                    return string.Format("{0} ", _authName);
                return string.Empty;
            }
            set { _authName = value; }
        }

        /// <summary>
        /// If set this will be used by the HmacHandlerHandler for data protection.
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }

        /// <summary>
        /// The TicketDataFormat is used to protect and unprotect the identity and other properties which are stored in the
        /// cookie value. If not provided one will be created using <see cref="DataProtectionProvider"/>.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> TicketDataFormat { get; set; }

        //Timeout for replay attacks
        public int RequestTimeLimit { get; set; }

        //Use Nonce's for additional security
        public bool EnableNonce
        {
            get
            {
                return _nonceEnabled;
            }
            set
            {
                _nonceEnabled = value;
            }
        }
    }
}
