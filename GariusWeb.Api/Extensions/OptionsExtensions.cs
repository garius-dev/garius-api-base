namespace GariusWeb.Api.Extensions
{
    public static class OptionsExtensions
    {
        public static IServiceCollection AddValidatedSettings<T>(
            this IServiceCollection services,
            IConfiguration configuration,
            string sectionName) where T : class
        {
            services.AddOptions<T>()
                .Bind(configuration.GetSection(sectionName))
                .ValidateDataAnnotations()
                .ValidateOnStart();

            return services;
        }
    }
}
