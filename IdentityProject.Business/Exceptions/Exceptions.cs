namespace IdentityProject.Business.Exceptions;
public class AuthenticationFailedException(string message) : Exception(message) { }
public class UserNotFoundException(string message) : Exception(message) { }
public class RoleNotFoundException(string message) : Exception(message) { }
public class UserRoleAssignmentFailedException(string message) : Exception(message) { }
public class EmailConfirmationFailedException(string message) : Exception(message) { }
public class TokenGenerationFailedException(string message) : Exception(message) { }