using System;

namespace AspNetMVC5Authorization.ViewModels
{
    public class UserSessionModel
    {
        public Guid UserId { get; set; }

        public string DisplayName { get; set; }
    }
}