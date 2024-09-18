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
using Iproj.Web.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

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
    private readonly AppSettings _appSettings;

    public AccountController(
        IIdentityServerInteractionService interaction,
        IClientStore clientStore,
        IAuthenticationSchemeProvider schemeProvider,
        IEventService events,
        SignInManager<IdentityUser> signInManager,
        IAuthService authService,
        IOptions<AppSettings> appSettings)
    {
        _interaction = interaction;
        _clientStore = clientStore;
        _schemeProvider = schemeProvider;
        _events = events;
        _signInManager = signInManager;
        _authService = authService;
        _appSettings = appSettings.Value;
    }

    public IActionResult Main()
    {
        return View();
    }

    [HttpGet]
    public async Task<IActionResult> Login(string returnUrl)
    {
        if (User.Identity!.IsAuthenticated)
        {
            if (!string.IsNullOrEmpty(returnUrl))
            {
                return Redirect(_appSettings.BaseUrl);  // Redirect to the original page they were trying to access
            }
            else
            {
                return RedirectToAction("Index", "Home"); // Redirect to home page if no returnUrl is specified
            }
        }

        var viewModel = await BuildLoginViewModelAsync(returnUrl);

        return View(viewModel);
    }


    [HttpGet]
    public async Task<IActionResult> Profile()
    {
        var data = HttpContext.User.GetSubId();
        var role = HttpContext.User.GetRole();

        var emailAdnId = Iproj.Helpers.TokenExtensions.GetEmailAndId(data);

        string email = emailAdnId.Gmail!;
        Guid? Id = emailAdnId.Id;

        var userData = await _signInManager.UserManager.FindByEmailAsync(email);

        if (userData != null)
        {
            UserViewModel userView = new UserViewModel()
            {
                Role = role,
                UserName = userData.UserName!,
                Email = email,
            };

            return View(userView);
        }
        return View();
    }

    [HttpGet]
    public IActionResult ChangePassword()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var data = HttpContext.User.GetSubId();
        var emailAdnId = Iproj.Helpers.TokenExtensions.GetEmailAndId(data);

        string email = emailAdnId.Gmail!;
        Guid? Id = emailAdnId.Id;

        var user = await _signInManager.UserManager.FindByEmailAsync(email);
        
        if (user == null)
        {
            return NotFound();
        }

        var result = await _signInManager.UserManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
        
        if (result.Succeeded)
        {
            return RedirectToAction("PasswordChangeSuccess");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View(model);
    }

    public IActionResult PasswordChangeSuccess()
    {
        return View();
    }


    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginInputModel model)
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

            // log in error save to logs
            await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId: context?.Client.ClientId));
            // input eror
            ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
        }

        // something went wrong, show form with error
        var viewModel = await BuildLoginViewModelAsync(model);

        return View(viewModel);
    }

    [HttpGet]
    public async Task<IActionResult> Logout(string logoutId)
    {
        var vm = await BuildLogoutViewModelAsync(logoutId);

        if (vm.ShowLogoutPrompt == false)
            return await Logout(vm);

        return View(vm);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout(LogoutInputModel model)
    {
        var viewModel = await BuildLoggedOutViewModelAsync(model.LogoutId);

        if (viewModel.PostLogoutRedirectUri == null)
            viewModel.PostLogoutRedirectUri = "/";

        if (User?.Identity!.IsAuthenticated == true)
        {
            await _signInManager.SignOutAsync();
            await HttpContext.SignOutAsync();

            // raise the logout event
            await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
        }

        return Redirect(viewModel.PostLogoutRedirectUri);
    }

    [HttpGet]
    public IActionResult AccessDenied()
    {
        return View();
    }

    private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
    {
        var viewModel = await BuildLoginViewModelAsync(model.ReturnUrl);
        viewModel.Username = model.Username;
        viewModel.RememberLogin = model.RememberLogin;
        return viewModel;
    }

    private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

        if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
        {
            var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

            var viewModel = new LoginViewModel
            {
                EnableLocalLogin = local,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint!,
            };

            if (!local)
            {
                viewModel.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context!.IdP } };
            }

            return viewModel;
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

        if (User?.Identity!.IsAuthenticated == true)
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

    private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
    {
        var viewModel = new LogoutViewModel 
        { 
            LogoutId = logoutId, 
            ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt 
        };

        if (User?.Identity!.IsAuthenticated != true)
        {
            viewModel.ShowLogoutPrompt = false;
            return viewModel;
        }

        var context = await _interaction.GetLogoutContextAsync(logoutId);

        if (context?.ShowSignoutPrompt == false)
        {
            viewModel.ShowLogoutPrompt = false;
            return viewModel;
        }

        return viewModel;
    }
}
