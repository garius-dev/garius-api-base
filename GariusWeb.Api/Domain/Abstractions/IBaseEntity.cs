namespace GariusWeb.Api.Domain.Abstractions
{
    public interface IBaseEntity
    {
        Guid Id { get; set; }
        DateTime CreatedAt { get; set; }
    }
}