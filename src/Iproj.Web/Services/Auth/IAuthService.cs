using Iproj.InputModels;
using Iproj.ViewModels;
using Microsoft.AspNetCore.Identity;

namespace Iproj.Services.Auth;

public interface IAuthService
{
    public Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl);
    public Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model);
    public Task<IdentityUser> LoginAsync(LoginInputModel model);
    public Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId);
}
