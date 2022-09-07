using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Logging;

namespace handeling_user_and_app_tokens
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            IdentityModelEventSource.ShowPII = true;

            services.AddControllers();
            services.AddApplicationInsightsTelemetry();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApi(this.Configuration, subscribeToJwtBearerMiddlewareDiagnosticsEvents: true);

            services.AddControllers(
                options =>
                {
                    var policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser()
                        .Build();

                    options.Filters.Add(new AuthorizeFilter(policy));
                });

            services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                var og_token_validated = options.Events.OnTokenValidated;

                options.Events.OnTokenValidated = async context =>
                {
                    if (!string.IsNullOrWhiteSpace(context.Principal?.Identity?.Name))
                    {
                        await og_token_validated.Invoke(context);
                    }
                };
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            IdentityModelEventSource.ShowPII = true;

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseAuthorization();
            app.UseAuthentication();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
