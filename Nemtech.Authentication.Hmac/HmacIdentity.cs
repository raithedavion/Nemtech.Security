using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Text;

namespace Nemtech.Authentication.Hmac
{
    /// <summary>
    /// Identity used for Hmac.  Doesn't have much purpose, but is required to created the "Ticket"
    /// </summary>
    public class HmacIdentity : GenericIdentity
    {
        public HmacIdentity(string accessID) : base(accessID)
        {
            AccessID = accessID;
        }

        public string AccessID { get; set; }
    }
}
