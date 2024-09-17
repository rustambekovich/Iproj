namespace Iproj.ViewModels
{
    public class LoggedOutViewModel
    {
        public string PostLogoutRedirectUri { get; set; } = string.Empty;

        public string ClientName { get; set; } = string.Empty;
        public string SignOutIframeUrl { get; set; } = string.Empty;

        public bool AutomaticRedirectAfterSignOut { get; set; }

        public string LogoutId { get; set; } = string.Empty;
        public bool TriggerExternalSignout => ExternalAuthenticationScheme != null;
        public string ExternalAuthenticationScheme { get; set; } = string.Empty;
    }
}