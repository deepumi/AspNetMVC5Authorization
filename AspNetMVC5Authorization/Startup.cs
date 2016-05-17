using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;

[assembly: OwinStartup(typeof(AspNetMVC5Authorization.Startup))]

namespace AspNetMVC5Authorization
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuthentication(app);
        }

        private void ConfigureAuthentication(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Auth/Login"),
                CookieName = "AuthCookie",
                CookieHttpOnly = true,
                ExpireTimeSpan = System.TimeSpan.FromHours(1),
                LogoutPath = new PathString("/Auth/Signout"),
                ReturnUrlParameter = "ReturnUrl",
                CookieSecure = CookieSecureOption.SameAsRequest,
                SlidingExpiration = true,
            });
        }
    }
}