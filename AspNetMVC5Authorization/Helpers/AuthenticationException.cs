using System;

namespace AspNetMVC5Authorization.Helpers
{
    public class AuthenticationException : Exception
    {
        public AuthenticationException(string message) : base(message)
        {

        }
    }
}