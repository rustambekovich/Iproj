using Iproj.Commons;
using Iproj.InputModels;

namespace Iproj.ViewModels;

public class LoginViewModel : LoginInputModel
{
    public bool EnableLocalLogin { get; set; } = true;
}