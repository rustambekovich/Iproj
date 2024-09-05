using Iproj.InputModels;

namespace Iproj.ViewModels;

public class LogoutViewModel : LogoutInputModel
{
    public bool ShowLogoutPrompt { get; set; } = true;
}
