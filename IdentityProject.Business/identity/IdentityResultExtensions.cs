using IdentityProject.Common.Dto;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.Business.identity;
public static class IdentityResultExtensions
{
    public static ResultDto ToApplicationResult(this IdentityResult result)
        => result.Succeeded
            ? ResultDto.Success()
            : ResultDto.Failure(result.Errors.Select(e => e.Description));

    public static ResultDto ToApplicationResult(this SignInResult signInResult)
        => signInResult.Succeeded
            ? ResultDto.Success()
            : ResultDto.FailureSignInResult(signInResult.IsLockedOut, signInResult.IsNotAllowed, signInResult.RequiresTwoFactor);
}