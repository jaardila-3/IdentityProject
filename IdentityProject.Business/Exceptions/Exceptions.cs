namespace IdentityProject.Business.Exceptions;
public class IdentitySignInManagerException(string message) : Exception(message) { }
public class UserNotFoundException(string message) : Exception(message) { }
public class IdentityUserManagerException(string message) : Exception(message) { }