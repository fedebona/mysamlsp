using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using System.Security.Authentication;
using System.Security.Claims;
using mysamlsp.Identity;

namespace mysamlsp.Controllers
{

    [Route("Auth")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";

        private readonly ILogger<AuthController> _logger;
        private readonly Saml2Configuration config;


        public AuthController(ILogger<AuthController> logger, Saml2Configuration config)
        {
            _logger = logger;

            this.config = config;
        }

        [Route("Login")]
        public IActionResult Login(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config)
            {
                //ForceAuthn = true,
                RequestedAuthnContext = new RequestedAuthnContext
                {
                    Comparison = AuthnContextComparisonTypes.Exact,
                    AuthnContextClassRef = new string[]
                    {
                        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
                    },
                },
            }).ToActionResult();
        }


        [Route("AssertionConsumerService")]
        public async Task<IActionResult> AssertionConsumerService()
        {
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(config);
            try
            {

                binding.ReadSamlResponse(Request.ToGenericHttpRequest(validate: true), saml2AuthnResponse);
                if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
                {
                    throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
                }
                binding.Unbind(Request.ToGenericHttpRequest(validate: true), saml2AuthnResponse);
                await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(CheckAssurance(claimsPrincipal)));

                var relayStateQuery = binding.GetRelayStateQuery();
                var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
                return Redirect(returnUrl);
            }
            catch (Exception ex)
            {

                ViewBag.Message = new Dictionary<string, string> { { "Exception", ex.Message }, { "StackTrace", ex.StackTrace} };
                return View();
            }
        }
        public IActionResult Index()
        {
            return View();
        }

        private ClaimsPrincipal CheckAssurance(ClaimsPrincipal claimsPrincipal)
        {

            return claimsPrincipal;
        }
    }
}