namespace Iproj.Commons
{
    public class AccountOptions
    {
        // log in local user login and password
        public static bool AllowLocalLogin = true;

        // login than remember me 
        public static bool AllowRememberLogin = true;

        // login than how much remember me days
        public static TimeSpan RememberMeLoginDuration = TimeSpan.FromDays(30);

        // show log out question
        public static bool ShowLogoutPrompt = true;

        // ridecrect sig out url
        public static bool AutomaticRedirectAfterSignOut = false;

        public static string InvalidCredentialsErrorMessage = "Invalid username or password";
    }
}
