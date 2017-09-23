// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;

namespace Nemtech.Authentication.Hmac
{
    /// <summary>
    /// Specifies events which the <see cref="HmacHandler"/> invokes to enable developer control over the authentication process.
    /// </summary>
    public class HmacEvents
    {
        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public Func<SignatureValidatedContext, Task> OnSignatureValidated { get; set; } = context => Task.CompletedTask;

        public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

        public virtual Task MessageReceived(MessageReceivedContext context) => OnMessageReceived(context);

        public virtual Task SignatureValidated(SignatureValidatedContext context) => OnSignatureValidated(context);
    }
}
