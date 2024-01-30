using Microsoft.AspNetCore.Identity.UI.Services;
using Mailjet.Client;
using Mailjet.Client.Resources;
using Newtonsoft.Json.Linq;
using Microsoft.Extensions.Configuration;

namespace IdentityProject.Services.SMTP.MailJet
{
    public class MailJetEmailSender(IConfiguration configuration) : IEmailSender
    {
        private readonly IConfiguration _configuration = configuration;
        public MailJetOptions? _mailJetOptions;

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            _mailJetOptions = _configuration.GetSection("MailJet").Get<MailJetOptions>()!;

            MailjetClient client = new(_mailJetOptions.ApiKey, _mailJetOptions.SecretKey)
            {
                Version = ApiVersion.V3_1,
            };
            MailjetRequest request = new MailjetRequest
            {
                Resource = Send.Resource,
            }
            .Property(Send.Messages, new JArray {
                new JObject {
                    {
                        "From", new JObject {
                                                {"Email", _mailJetOptions.FromEmail},
                                                {"Name", _mailJetOptions.FromName}
                                            }
                    },
                    {
                        "To", new JArray { new JObject {
                                                            { "Email", email },
                                                            { "Name", "Apreciado Cliente" }
                                                        }
                                        }
                    },
                    {
                        "Subject", subject
                    },
                    {
                        "HTMLPart", htmlMessage
                    }
                }
            });

            MailjetResponse response = await client.PostAsync(request);
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine(string.Format("Total: {0}, Count: {1}\n", response.GetTotal(), response.GetCount()));
                Console.WriteLine(response.GetData());
            }
            else
            {
                Console.WriteLine(string.Format("StatusCode: {0}\n", response.StatusCode));
                Console.WriteLine(string.Format("ErrorInfo: {0}\n", response.GetErrorInfo()));
                Console.WriteLine(response.GetData());
                Console.WriteLine(string.Format("ErrorMessage: {0}\n", response.GetErrorMessage()));
                Console.Error.WriteLine("No se pudo enviar el email de confirmación por error de MailJet.");
            }
        }

    }
}