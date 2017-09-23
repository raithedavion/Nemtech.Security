using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication;

namespace Nemtech.Authentication.Hmac
{
    public class HmacPostConfigureOptions : IPostConfigureOptions<HmacOptions>
    {
        private readonly IDataProtectionProvider _dp;

        public HmacPostConfigureOptions(IDataProtectionProvider dataProtection)
        {
            _dp = dataProtection;
        }

        public void PostConfigure(string name, HmacOptions options)
        {
            options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;
            if (options.TicketDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                    typeof(HmacHandler).FullName, name, "v1");
                options.TicketDataFormat = new TicketDataFormat(dataProtector);
            }
        }
    }
}
