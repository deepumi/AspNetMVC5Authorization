# AspNetMVC5Authorization
Sample app for creating Asp.Net MVC 5 authorization using claims principal

## Step1
* File -> New Project -> Asp.Net Web Application -> Asp.Net 4.5.2 Templates
* Choose empty MVC project template

## Step2
* Install following nuget packages 
  * Microsoft.AspNet.Identity.Core
  * Microsoft.AspNet.Identity.Owin
  * Microsoft.Owin
  * Microsoft.Owin.Host.SystemWeb
  * Microsoft.Owin.Security
  * Microsoft.Owin.Security.Cookies
  * Microsoft.Owin.Security.OAuth
  * Owin

## Step3
* Create a Owin Startup class and decorate with assembly attribute OwinStartup.
  ```c#
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
                  LoginPath = new PathString("/Auth/Login"), //sign page
                  CookieName = "AuthCookie",
                  CookieHttpOnly = true,
                  ExpireTimeSpan = System.TimeSpan.FromHours(1),
                  LogoutPath = new PathString("/Auth/Signout"), //sign out page
                  ReturnUrlParameter = "ReturnUrl",
                  CookieSecure = CookieSecureOption.SameAsRequest, //Use CookieSecureOption.Always if you intend to serve cookie in SSL/TLS (Https)
                  SlidingExpiration = true,
              });
          }
      }
  }
  
  ```
## Step4
* Create list of claims for the specific user with roles and other information
  ```c#
  internal class AuthenticationHelper
  {
     internal static List<Claim> CreateClaim(UserSessionModel userSessionModel,params string[] roles) //Single or multiple roles
     {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userSessionModel.UserId.ToString()),  //User ideitifer
            new Claim(ClaimTypes.Name, userSessionModel.DisplayName),  //Username
            new Claim(Constants.UserSession, userSessionModel.ToJson()) //Custom entity with user info
        };

        foreach (var role in roles) //custom roles goes here
        {
            claims.Add(new Claim(ClaimTypes.Role, role, ClaimValueTypes.String, Constants.Issuer));
        }
        return claims;
     }
  }
  ```

## Step5
* Create Authentication controller and process of the rest of the Authentication
```c#
    using Microsoft.AspNet.Identity;
    using Microsoft.Owin.Security;
    using System.Security.Claims;
    
    public class AuthController : BaseController
    {
      private IAuthenticationManager AuthenticationManager
      {
          get { return HttpContext.GetOwinContext().Authentication; }
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
  
              var userSession = Authenticate(vm); // Validate authentication from db or other source.
  
              if (userSession != null) //create claim with user info.
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
    }
```
## Step6
* Get the custom ojbect obect from Claim
```c#
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
```
## Step7
```c#
[Authorize(ClaimType = ClaimTypes.Role, ClaimValue = "Contributor,User")]
public ActionResult Secure()
{
    var userSessionModel = UserSessionModel; //Get custom object from Security claim.
    return View();
}
```
## Finally Custom Authorize attribute code
```c#
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
```
