namespace GariusWeb.Api.Extensions
{
    public static class CorsExtensions
    {
        public static IServiceCollection AddCustomCors(this IServiceCollection services, IWebHostEnvironment env)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("AllowSpecificOrigins", policy =>
                {
                    if (env.IsDevelopment() || env.IsEnvironment("LocalDevelopmentWithNgrok"))
                    {
                        policy.WithOrigins(
                                "http://localhost:5173",
                                "https://localhost:5173",
                                "https://jackal-infinite-penguin.ngrok-free.app",
                                "https://preview--garius-flow-control.lovable.app",
                                "https://lovable.dev/projects/13fb6a64-b608-471d-b202-735249a9d63d",
                                "https://localhost:7223",
                                "http://localhost:8080"
                            )
                            .AllowAnyHeader()
                            .AllowAnyMethod()
                            .AllowCredentials();
                    }
                    else
                    {
                        var configuration = services.BuildServiceProvider().GetService<IConfiguration>();

                        if (configuration != null)
                        {
                            var allowedOrigins = configuration.GetSection("CorsSettings:AllowedOrigins").Get<string[]>();
                            if (allowedOrigins != null && allowedOrigins.Length > 0)
                            {
                                policy.WithOrigins(allowedOrigins) // Usa as origens da configuração
                                      .AllowAnyHeader()
                                      .AllowAnyMethod();
                            }
                        }
                    }
                });
            });

            return services;
        }

        public static IApplicationBuilder UseCustomCors(this IApplicationBuilder app)
        {
            app.UseCors("AllowSpecificOrigins");
            return app;
        }
    }
}
