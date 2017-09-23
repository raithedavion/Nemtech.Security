using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;

namespace Nemtech.Authentication.Hmac
{
    /// <summary>
    /// Add "AddHmac" to the UseAuthentication() method when configuring services
    /// </summary>
    public static class HmacExtensions
    {
        public static AuthenticationBuilder AddHmac(this AuthenticationBuilder builder)
            => builder.AddHmac(HmacDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddHmac(this AuthenticationBuilder builder, Action<HmacOptions> configureOptions)
            => builder.AddHmac(HmacDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddHmac(this AuthenticationBuilder builder, string authenticationScheme, Action<HmacOptions> configureOptions)
            => builder.AddHmac(authenticationScheme, displayName: null, configureOptions: configureOptions);

        public static AuthenticationBuilder AddHmac(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<HmacOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<HmacOptions>, HmacPostConfigureOptions>());
            return builder.AddScheme<HmacOptions, HmacHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
