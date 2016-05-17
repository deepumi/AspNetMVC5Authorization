namespace AspNetMVC5Authorization.Helpers
{
    using System.Collections.Generic;
    using System.Security.Claims;
    using ViewModels;

    internal class AuthenticationHelper
    {
        internal static List<Claim> CreateClaim(UserSessionModel userSessionModel,params string[] roles)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userSessionModel.UserId.ToString()),
                new Claim(ClaimTypes.Name, userSessionModel.DisplayName),
                new Claim(Constants.UserSession, userSessionModel.ToJson())
            };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role, ClaimValueTypes.String, Constants.Issuer));
            }
            return claims;
        }
    }
}