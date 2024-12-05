using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Cookies;
using Azure.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.OAuth;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();
builder.Configuration.AddEnvironmentVariables();

try
{
    if (builder.Configuration["ASPNETCORE_ENVIRONMENT"] == "Development")
        builder.Configuration.AddAzureKeyVault(new Uri("https://linkupguidedkeyvaults.vault.azure.net/"), new DefaultAzureCredential());
    else
        builder.Configuration.AddAzureKeyVault(new Uri("https://linkupguidedkeyvaults.vault.azure.net/"), new ManagedIdentityCredential());
}
catch(Exception exception)
{
    System.Diagnostics.Debug.WriteLine(exception);
}
finally
{
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.Name = "linkup-e6ftf8exadfngact.westeurope-01.Auth";
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromDays(30);
    })
    //.AddGoogle(options =>
    //{
    //    options.ClientId = builder.Configuration["GOOGLE_AUTH_CLIENT_ID"] ?? "aa";
    //    options.ClientSecret = builder.Configuration["google-provider-auth-secret"] ?? "bb";
    //    options.CallbackPath = "/Redirect";

    //    options.Scope.Clear();
    //    options.Scope.Add("email");
    //    options.Scope.Add("profile");
    //    options.Scope.Add("openid");

    //    options.Events = new OAuthEvents
    //    {
    //        OnTicketReceived = context =>
    //        {
    //            var identity = context.Principal.Identity as ClaimsIdentity;
    //            if (identity != null)
    //            {
    //                identity.AddClaim(new Claim("access_token", builder.Configuration["access-token-function-app"]));
    //            }

    //            return Task.CompletedTask;
    //        }
    //    };
    //})
    .AddOpenIdConnect(options =>
    {
        options.ClientId = builder.Configuration["MICROSOFT_CLIENT_ID"] ?? "aa";
        options.ClientSecret = builder.Configuration["MICROSOFT_PROVIDER_AUTHENTICATION_SECRET"] ?? "bb";
        options.Authority = $"https://login.microsoftonline.com/common/v2.0";
        options.CallbackPath = "/Index";

        options.ResponseType = "code id_token";

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        //options.Scope.Add("api://812fda42-4d5e-4f66-a8be-7878c992f6de/.default");

        options.TokenValidationParameters = new TokenValidationParameters
        {
            IssuerValidator = (issuer, token, parameters) =>
            {
                if (issuer.StartsWith("https://login.microsoftonline.com/") ||
                    issuer.StartsWith("https://login.microsoft.com/"))
                {
                    return issuer;
                }

                throw new SecurityTokenInvalidIssuerException($"Issuer {issuer} is not valid.");
            },
        };

        options.Events = new OpenIdConnectEvents
        {
            OnTokenResponseReceived = context =>
            {
                var accessToken = context.TokenEndpointResponse.AccessToken;

                var identity = context.Principal.Identity as ClaimsIdentity;
                if (identity != null && accessToken != null)
                {
                    identity.AddClaim(new Claim("access_token", builder.Configuration["access-token-function-app"]));
                }

                return Task.CompletedTask;
            }
        };
    });

    builder.Services.AddSession(options =>
    {
        options.Cookie.Name = "linkup-e6ftf8exadfngact.westeurope-01.Session";
        options.IdleTimeout = TimeSpan.FromMinutes(30);
        options.Cookie.IsEssential = true;
    });

    var app = builder.Build();

    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Error");
        app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseStaticFiles();
    app.UseRouting();
    app.UseSession();
    app.UseAuthentication();
    app.UseAuthorization();

    app.UseStatusCodePagesWithReExecute("/Index");
    app.MapRazorPages();

    app.Run();
}


public static class Constant
{
    public static int SIZE_HASH = 42;
}