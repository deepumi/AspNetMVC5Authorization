namespace AspNetMVC5Authorization.Controllers
{
    using System.Linq;
    using System.Security.Claims;
    using System.Web.Mvc;
    using System.Web.Routing;
    using Helpers;
    using ViewModels;
    public class BaseController : Controller
    {
        protected internal UserSessionModel UserSessionModel { get; private set; }

        protected override void Initialize(RequestContext requestContext)
        {
            base.Initialize(requestContext);
            var user = User as ClaimsPrincipal;
            if (user != null)
            {
                var claims = user.Claims.ToList();
                var sessionClaim = claims.FirstOrDefault(o => o.Type == Constants.UserSession);
                if (sessionClaim != null)
                {
                    UserSessionModel = sessionClaim.Value.ToObject<UserSessionModel>();
                }
            }
        }
    }
}