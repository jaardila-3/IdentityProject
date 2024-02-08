namespace IdentityProject.Common.Dto;

public record UserDto(string? Id, string? UserName, string? Email, string? Name, string? Url, int? CountryCode, string? PhoneNumber, string? Country, string? City, string? Address, DateTime? Birthdate, bool State, DateTimeOffset? LockoutEnd);
