using System.Security.Claims;
using System.Web.Mvc;

namespace AspNetMVC5Authorization.Controllers
{
    public class HomeController : BaseController
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize(ClaimType = ClaimTypes.Role, ClaimValue = Helpers.Constants.UserRoles.Admin + "," + Helpers.Constants.UserRoles.User)]
        public ActionResult Secure()
        {
            var userSessionModel = UserSessionModel;

            return View();
        }
    }
}