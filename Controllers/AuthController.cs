using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using System.Security.Authentication;
using System.Security.Claims;
using mysamlsp.Identity;
using System.Web;
using System;
using mysamlsp.Models;

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
            //read a key from appsettings.json
            //config.Issuer = 
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

        [Route("LoginForm")]
        public IActionResult LoginForm(string returnUrl = null)
        {

            var binding = new Saml2PostBinding();
            var saml2LoginRequest = new Saml2AuthnRequest(config)
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
            };

            ViewBag.Message = new Dictionary<string, string> { { "Content", binding.Bind(saml2LoginRequest).PostContent } };
            return View();

        }

        //This method is used to create a login request and return the SAMLRequest and IdPUrl
        //The SAMLRequest is not base64 encoded but inflated
        [HttpGet]
        [Route("LoginRequestCreate")]
        public IActionResult LoginRequestCreate(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });
            //read a key from appsettings.json
            //config.Issuer = 
            var calculatedBinding = binding.Bind(new Saml2AuthnRequest(config)
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
            });

            var message = new Dictionary<string, string> {
                { "IdPUrl", calculatedBinding.RedirectLocation.GetLeftPart(UriPartial.Path)},
                { "SAMLRequest", HttpUtility.ParseQueryString(calculatedBinding.RedirectLocation.Query)["SAMLRequest"] }
            };
            return Json(message);
        }

        [Route("AssertionConsumerService")]
        public async Task<IActionResult> AssertionConsumerService()
        {
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(config);
            var currentStage = "";
            try
            {

                binding.ReadSamlResponse(Request.ToGenericHttpRequest(validate: true), saml2AuthnResponse);
                currentStage = "response read";
                if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
                {
                    throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
                }
                currentStage = string.Format("response status {0}", saml2AuthnResponse.Status);
                binding.Unbind(Request.ToGenericHttpRequest(validate: true), saml2AuthnResponse);
                currentStage = string.Format("Unbind");
                await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(CheckAssurance(claimsPrincipal)));

                var relayStateQuery = binding.GetRelayStateQuery();
                var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
                return View(new AssertionModel()
                {
                    UserName = saml2AuthnResponse.ClaimsIdentity.Name?? "No Name",
                    Provider = "saml2",
                });
                //return Redirect(returnUrl);
            }
            catch (Exception ex)
            {

                ViewBag.Message = new Dictionary<string, string> { { "Stage", currentStage }, { "Exception", ex.Message }, { "StackTrace", ex.StackTrace } };
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