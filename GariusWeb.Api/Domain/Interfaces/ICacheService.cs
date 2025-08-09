namespace GariusWeb.Api.Domain.Interfaces
{
    public interface ICacheService
    {
        Task<T?> GetAsync<T>(string key);
        Task SetAsync<T>(string key, T value, TimeSpan? expiration = null);
        Task RemoveAsync(string key);
        Task<bool> ExistsAsync(string key);
        Task SetPersistentAsync<T>(string key, T value); // Sem expiração
    }
}
