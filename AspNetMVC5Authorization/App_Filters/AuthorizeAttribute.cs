namespace AspNetMVC5Authorization
{
    using Helpers;
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Web.Mvc;

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class AuthorizeAttribute : System.Web.Mvc.AuthorizeAttribute
    {
        public string ClaimType { get; set; }
        public string ClaimValue { get; set; }

        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            base.OnAuthorization(filterContext);
            var principal = filterContext.RequestContext.HttpContext.User as ClaimsPrincipal;
            
            if (!principal.Identity.IsAuthenticated)
            {
                filterContext.Result = new RedirectResult("~/auth/signin");
                return;
            }

            var claimValue = ClaimValue.Split(',');
            if (!(principal.HasClaim(x => x.Type == ClaimType && claimValue.Any(v => v == x.Value) && x.Issuer == Constants.Issuer)))
            {
                filterContext.Result = new RedirectResult("~/Unauthorize.html");
            }
        }
    }
}