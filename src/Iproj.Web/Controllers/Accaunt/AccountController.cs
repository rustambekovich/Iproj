using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Iproj.Commons;
using Iproj.Helpers;
using Iproj.InputModels;
using Iproj.Services.Auth;
using Iproj.ViewModels;
using Iproj.Web.Commons;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Iproj.Controllers.Accaunt;

[SecurityHeaders]
[AllowAnonymous]
public class AccountController : Controller
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IClientStore _clientStore;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IEventService _events;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IAuthService _authService;

    public AccountController(
        IIdentityServerInteractionService interaction,
        IClientStore clientStore,
        IAuthenticationSchemeProvider schemeProvider,
        IEventService events,
        SignInManager<IdentityUser> signInManager,
        IAuthService authService)
    {
        _interaction = interaction;
        _clientStore = clientStore;
        _schemeProvider = schemeProvider;
        _events = events;
        _signInManager = signInManager;
        _authService = authService;
    }

    [HttpGet]
    public async Task<IActionResult> Login(string returnUrl)
    {

        var vm = await BuildLoginViewModelAsync(returnUrl);

        return View(vm);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginInputModel model, string button)
    {
        var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

        if (ModelState.IsValid)
        {
            var user = await _authService.LoginAsync(model);

            if (user != null)
            {
                var userCalms = await _signInManager.UserManager.GetClaimsAsync(user);

                await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));

                AuthenticationProperties props = null!;
                if (AccountOptions.AllowRememberLogin && model.RememberLogin)
                {
                    props = new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                    };
                };

                var subAndEmail = user.Id + '|' + user.Email;
                var isuser = new IdentityServerUser(subAndEmail)
                {
                    DisplayName = user.UserName,
                    AdditionalClaims = userCalms,
                };

                await HttpContext.SignInAsync(isuser, props);

                if (context != null)
                {
                    // check web or mobil and desktop
                    if (context.IsNativeClient())
                        return this.LoadingPage("Redirect", model.ReturnUrl);

                    return Redirect(model.ReturnUrl);
                }

                if (Url.IsLocalUrl(model.ReturnUrl))
                {
                    return Redirect(model.ReturnUrl);
                }
                else if (string.IsNullOrEmpty(model.ReturnUrl))
                {
                    return Redirect("~/");
                }
                else
                {
                    throw new Exception("invalid return URL");
                }
            }

            await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId: context?.Client.ClientId));

            ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
        }

        // something went wrong, show form with error
        var vm = await BuildLoginViewModelAsync(model);
        return View(vm);
    }

    [HttpGet]
    public async Task<IActionResult> Logout(string logoutId)
    {
        var vm = await _authService.BuildLogoutViewModelAsync(logoutId);

        if (vm.ShowLogoutPrompt == false)
            return await Logout(vm);

        return View(vm);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout(LogoutInputModel model)
    {
        var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

        if (User?.Identity!.IsAuthenticated == true)
        {
            // delete local authentication cookie
            await _signInManager.SignOutAsync();
            await HttpContext.SignOutAsync();

            // raise the logout event
            await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
        }

        if (vm.TriggerExternalSignout)
        {
            string url = Url.Action("Logout", new { logoutId = vm.LogoutId })!;

            return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
        }

        return Redirect(vm.PostLogoutRedirectUri); // added

        //return View("LoggedOut", vm);
    }

    [HttpGet]
    public IActionResult AccessDenied()
    {
        return View();
    }

    private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
    {
        var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
        vm.Username = model.Username;
        vm.RememberLogin = model.RememberLogin;
        return vm;
    }

    private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

        if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
        {
            var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

            var vm = new LoginViewModel
            {
                EnableLocalLogin = local,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint!,
            };

            if (!local)
            {
                vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
            }

            return vm;
        }

        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ExternalProvider
            {
                DisplayName = x.DisplayName ?? x.Name,
                AuthenticationScheme = x.Name
            }).ToList();

        var allowLocal = true;

        if (context?.Client.ClientId != null)
        {
            var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
            if (client != null)
            {
                allowLocal = client.EnableLocalLogin;

                if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                {
                    providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                }
            }
        }

        return new LoginViewModel
        {
            AllowRememberLogin = AccountOptions.AllowRememberLogin,
            EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
            ReturnUrl = returnUrl,
            Username = context?.LoginHint!,
            ExternalProviders = providers.ToArray()
        };
    }

    private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
    {
        // get context information (client name, post logout redirect URI and iframe for federated signout)
        var logout = await _interaction.GetLogoutContextAsync(logoutId);

        var vm = new LoggedOutViewModel
        {
            AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
            PostLogoutRedirectUri = logout?.PostLogoutRedirectUri!,
            ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
            SignOutIframeUrl = logout?.SignOutIFrameUrl!,
            LogoutId = logoutId
        };

        if (User?.Identity.IsAuthenticated == true)
        {
            var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;

            if (idp != null && idp != IdentityServerConstants.LocalIdentityProvider)
            {
                var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);

                if (providerSupportsSignout)
                {
                    if (vm.LogoutId == null)
                        vm.LogoutId = await _interaction.CreateLogoutContextAsync();

                    vm.ExternalAuthenticationScheme = idp;
                }
            }
        }

        return vm;
    }
}
