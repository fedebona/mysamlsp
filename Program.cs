using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.Extensions.Configuration;
using System.Runtime.CompilerServices;

var builder = WebApplication.CreateBuilder(args);

//bind configuration from appsettings.json to Saml2Configuration

builder.Services.BindConfig<Saml2Configuration>(builder.Configuration, "Saml2", (serviceProvider, saml2Configuration) =>
{
    saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);

    var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
    var entityDescriptor = new EntityDescriptor();
    entityDescriptor.ReadIdPSsoDescriptorFromFile(builder.Configuration["Saml2:IdPMetadataFile"]);
    if (entityDescriptor.IdPSsoDescriptor != null)
    {
        saml2Configuration.AllowedIssuer = entityDescriptor.EntityId;
        saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
        saml2Configuration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
        saml2Configuration.AudienceRestricted = false;
        foreach (var signingCertificate in entityDescriptor.IdPSsoDescriptor.SigningCertificates)
        {
            if (signingCertificate.IsValidLocalTime())
            {
                saml2Configuration.SignatureValidationCertificates.Add(signingCertificate);
            }
        }
        if (saml2Configuration.SignatureValidationCertificates.Count <= 0)
        {
            throw new Exception("The IdP signing certificates has expired.");
        }
        if (entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.HasValue)
        {
            saml2Configuration.SignAuthnRequest = entityDescriptor.IdPSsoDescriptor.WantAuthnRequestsSigned.Value;
        }
        //cast the string to the enum
        saml2Configuration.CertificateValidationMode = (System.ServiceModel.Security.X509CertificateValidationMode)Enum.Parse(typeof(System.ServiceModel.Security.X509CertificateValidationMode), builder.Configuration["Saml2:CertificateValidationMode"]);
        saml2Configuration.Issuer = builder.Configuration["Saml2:Issuer"];
    }
    else
    {
        throw new Exception("IdPSsoDescriptor not loaded from metadata.");
    }

    return saml2Configuration;
});

builder.Services.AddSaml2(slidingExpiration: true);
builder.Services.AddHttpClient();

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "auth",
    pattern: "{controller=Auth}/{action=Index}/{id?}");

app.Run();
