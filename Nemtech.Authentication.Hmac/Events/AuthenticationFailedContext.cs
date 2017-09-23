// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

namespace Nemtech.Authentication.Hmac
{
    public class AuthenticationFailedContext : ResultContext<HmacOptions>
    {
        public AuthenticationFailedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            HmacOptions options)
            : base(context, scheme, options) { }

        public Exception Exception { get; set; }
    }
}