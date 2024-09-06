using IdentityModel;
using IdentityServer4;
using IdentityServer4.EntityFramework.Stores;
using IdentityServer4.Events;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Iproj.Commons;
using Iproj.InputModels;
using Iproj.Models.Users;
using Iproj.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.VisualBasic;
using System;

namespace Iproj.Services.Auth;

public class AuthService : IAuthService
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IClientStore _clientStore;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IEventService _events;
    private readonly SignInManager<IdentityUser> _signInManager;

    public AuthService(
        IIdentityServerInteractionService interaction,
        IClientStore clientStore,
        IAuthenticationSchemeProvider schemeProvider,
        IEventService events,
        SignInManager<IdentityUser> signInManager)
    {
        _interaction = interaction;
        _clientStore = clientStore;
        _schemeProvider = schemeProvider;
        _events = events;
        _signInManager = signInManager;
    }
    public async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

        if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
        {
            var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;

            var vm = new LoginViewModel
            {
                EnableLocalLogin = local,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint!,
            };

            return vm;
        }

        var allowLocal = true;

        if (context?.Client.ClientId != null)
        {
            var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);

            if (client != null)
            {
                allowLocal = client.EnableLocalLogin;
            }
        }

        return new LoginViewModel
        {
            EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
            ReturnUrl = returnUrl,
            Username = context?.LoginHint!,
        };
    }

    public async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
    {
        var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
        vm.Username = model.Username;
        return vm;
    }

    public async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
    {
        var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

        var context = await _interaction.GetLogoutContextAsync(logoutId);
        if (context?.ShowSignoutPrompt == false)
        {
            // it's safe to automatically sign-out
            vm.ShowLogoutPrompt = false;
            return vm;
        }

        return vm;
    }

    public async Task<IdentityUser> LoginAsync(LoginInputModel model)
    {
        // check if we are in the context of an authorization request
        var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

        var user = await _signInManager.UserManager.FindByEmailAsync(model.Username);

        if (user != null)
        {
            var validUser = await _signInManager.CheckPasswordSignInAsync(user, model.Password, true);
            // validate username/password
            if (validUser == Microsoft.AspNetCore.Identity.SignInResult.Success)
            {
                return user;
            }
            else
            {
                return null;
            }
        }
        else
        {
            return null;
        }
    }

}
