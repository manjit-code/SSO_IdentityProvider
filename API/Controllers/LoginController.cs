using Microsoft.AspNetCore.Mvc;
using SSO_IdentityProvider.Domain.Interfaces;

[Route("")]
public class LoginController : Controller
{
    private readonly ILdapAuthenticator _ldapAuthenticator;

    public LoginController(ILdapAuthenticator ldapAuthenticator)
    {
        _ldapAuthenticator = ldapAuthenticator;
    }

    [HttpGet("login")]
    public IActionResult Login(string returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl)) return BadRequest("returnUrl missing in GET /login");

        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }


    [HttpPost("login")]
    public async Task<IActionResult> Login(string username, string password, string returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
            return BadRequest("Missing returnUrl");

        var conn = await _ldapAuthenticator.BindAsUserAsync(username, password);
        if (conn == null)
            return Unauthorized("Invalid credentials");

        HttpContext.Session.SetString("username", username);

        return Redirect(returnUrl);
    }
}
