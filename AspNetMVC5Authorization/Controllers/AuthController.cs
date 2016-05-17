namespace AspNetMVC5Authorization.Controllers
{
    using Microsoft.AspNet.Identity;
    using Microsoft.Owin.Security;
    using System;
    using System.Security.Claims;
    using System.Web;
    using System.Web.Mvc;
    using Helpers;
    using ViewModels;

    public class AuthController : BaseController
    {
        [HttpGet]
        public ActionResult SignIn()
        {
            if(UserSessionModel != null)
            {
                return Redirect("~/");
            }
            return View();
        }

        [HttpPost,ValidateAntiForgeryToken]
        public ActionResult SignIn(SignInViewModel vm,string returnUrl = default(string))
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    vm.ErrorMessage = "Email address and Password are required fields";
                    return View(vm);
                }

                var userSession = Authenticate(vm);

                if (userSession != null)
                {
                    var identity = new ClaimsIdentity(AuthenticationHelper.CreateClaim(userSession, 
                                                        Helpers.Constants.UserRoles.Admin, 
                                                        Helpers.Constants.UserRoles.User),
                                                        DefaultAuthenticationTypes.ApplicationCookie
                                                        );
                    AuthenticationManager.SignIn(new AuthenticationProperties()
                    {
                        AllowRefresh = true,
                        IsPersistent = true,
                        ExpiresUtc = DateTime.UtcNow.AddHours(1)
                    }, identity);

                    if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl)) return Redirect(returnUrl);

                    return RedirectToAction("index", "home");
                }
            }
            catch (AuthenticationException e)
            {
                vm.ErrorMessage = e.Message;
            }
            return View(vm);
        }

        private UserSessionModel Authenticate(SignInViewModel vm)
        {
            if (vm.Email != "email@email.com" || vm.Password != "password") throw new AuthenticationException("Login failed. Incorrect email address or password");

            return new UserSessionModel
            {
                UserId = Guid.NewGuid(),
                DisplayName = "Deepu Madhusoodanan"
            };
        }

        public ActionResult Signout()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie,DefaultAuthenticationTypes.ExternalCookie);
            return Redirect("~/");
        }

        private IAuthenticationManager AuthenticationManager
        {
            get { return HttpContext.GetOwinContext().Authentication; }
        }
    }
}