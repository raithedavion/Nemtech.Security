using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;

namespace Nemtech.Authentication.Hmac
{
    public class MessageReceivedContext : ResultContext<HmacOptions>
    {
        public MessageReceivedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            HmacOptions options)
            : base(context, scheme, options) { }

        /// <summary>
        /// Signature. This will give the application an opportunity to retrieve a Signature from an alternative location.
        /// </summary>
        public string Signature { get; set; }
    }
}
