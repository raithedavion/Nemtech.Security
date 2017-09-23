// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Nemtech.Authentication.Hmac
{
    public class SignatureValidatedContext : ResultContext<HmacOptions>
    {
        public SignatureValidatedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            HmacOptions options)
            : base(context, scheme, options) { }

    }
}
