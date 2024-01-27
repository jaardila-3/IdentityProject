namespace IdentityProject.Common.Dto;
public record ResultDto(bool Succeeded, IEnumerable<string> Errors, bool IsLockedOut = false, bool IsNotAllowed = false, bool RequiresTwoFactor = false)
{
    public static ResultDto Success() => new(true, []);
    public static ResultDto Failure(IEnumerable<string> errors) => new(false, errors);
    public static ResultDto FailureSignInResult(bool IsLockedOut, bool IsNotAllowed, bool RequiresTwoFactor)
        => new(false, [], IsLockedOut, IsNotAllowed, RequiresTwoFactor);
}