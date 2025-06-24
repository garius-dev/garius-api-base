namespace GariusWeb.Api.Helpers
{
    public class ApiResponse<T>
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
        public T? Data { get; init; }
        public int StatusCode { get; init; }

        public static ApiResponse<T> Ok(T data, string message = "Sucesso") =>
            new() { Success = true, Data = data, Message = message, StatusCode = 200 };

        public static ApiResponse<T> Fail(string message, int statusCode = 400) =>
            new() { Success = false, Data = default, Message = message, StatusCode = statusCode };
    }
}
