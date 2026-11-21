namespace Saas.Identity.Domain.Common;

public sealed record DomainError(
    string Code,
    string Message,
    int HttpStatus,
    IReadOnlyDictionary<string, object?>? Extensions = null);

public class Result
{
    public static readonly DomainError None = new(string.Empty, string.Empty, 200);

    protected Result(bool isSuccess, DomainError error)
    {
        if (isSuccess && error != None)
        {
            throw new InvalidOperationException("Un resultado exitoso no puede contener un error.");
        }

        if (!isSuccess && error == None)
        {
            throw new InvalidOperationException("Un resultado fallido debe especificar un error.");
        }

        IsSuccess = isSuccess;
        Error = error;
    }

    public bool IsSuccess { get; }
    public bool IsFailure => !IsSuccess;
    public DomainError Error { get; }

    public static Result Success() => new(true, None);

    public static Result Failure(DomainError error) => new(false, error);

    public static Result<T> Success<T>(T value) => new(value, true, None);

    public static Result<T> Failure<T>(DomainError error) => new(default!, false, error);
}

public sealed class Result<T> : Result
{
    private readonly T _value;

    internal Result(T value, bool isSuccess, DomainError error)
        : base(isSuccess, error)
    {
        _value = value;
    }

    public T Value => IsSuccess
        ? _value
        : throw new InvalidOperationException("No se puede leer el valor de un resultado fallido.");
}
