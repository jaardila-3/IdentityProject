namespace IdentityProject.Common.Dto;

public record RoleDto(string? Id, string? Name);
public record UserRolesDto(string? UserId, string? RoleId);