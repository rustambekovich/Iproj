using IdentityServer4.Models;

namespace Iproj.ViewModels
{
    public class ErrorViewModel
    {
        public ErrorViewModel()
        {}

        public ErrorViewModel(string error)
        {
            Error = new ErrorMessage { Error = error };
        }

        public ErrorMessage Error { get; set; }
    }
}