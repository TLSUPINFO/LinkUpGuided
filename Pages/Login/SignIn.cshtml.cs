using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace webapp_sam_lab13.Pages;

public class AuthMethod
{
    public AuthMethod(string _name, string _url)
    {
        Name = _name;
        Url = _url;
    }

    public string Name { get; set; }

    public string Url { get; set; }
}

public class SignInModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;
    private readonly IConfiguration _configuration;

    public string RedirectURL => Request.Scheme + "://" + Request.Host;

    public AuthMethod[] AuthMethods
    {
        get
        {
            AuthMethod[] Methods = new AuthMethod[2];
            if (_configuration != null)
            {
                Methods[0] = _configuration["ENABLE_GOOGLE_AUTHENTIFICATION"] == "true" ? new AuthMethod("Google", $"https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?response_type=code&client_id={_configuration["GOOGLE_AUTH_CLIENT_ID"]}&redirect_uri={RedirectURL + "/.auth/login/google/callback"}&scope=openid%20profile%20email&state=redir%3D%252F%26nonce%3Daac9b80cb6304c1bb296800626f9b112_20241117103850&service=lso&o2v=2&ddm=1&flowName=GeneralOAuthFlow&prompt=login") : null;
                Methods[1] = _configuration["ENABLE_MICROSOFT_AUTHENTIFICATION"] == "true" ? new AuthMethod("Microsoft", $"https://login.microsoftonline.com/1dc8f08a-46f6-4cdb-b8ff-03e46c14979d/oauth2/v2.0/authorize?response_type=code+id_token&redirect_uri=https%3A%2F%2Flinkup-e6ftf8exadfngact.westeurope-01.azurewebsites.net%2F.auth%2Flogin%2Faad%2Fcallback&client_id=dd2e4718-a643-4230-b222-b46fa96f7b01&scope=openid+profile+email&response_mode=form_post&nonce=0b0ed4ad663c47f8a729b54c2657e711_20241117104452&state=redir%3D%252F&sso_reload=true") : null;
            }

            return Methods;
        }
    }

    public SignInModel(ILogger<IndexModel> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    public void OnGet()
    {
    }

    public IActionResult OnPostLoginAsync(string authMethod)
    {
        var properties = new AuthenticationProperties { RedirectUri = RedirectURL };
        if (authMethod == "Google")
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        else
            return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
    }
}
