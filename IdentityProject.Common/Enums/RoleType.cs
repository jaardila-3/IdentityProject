using System.ComponentModel;

namespace IdentityProject.Common.Enums
{
    public static class RoleTypeString
    {
        public const string Administrator = "Administrador";
        public const string RegisteredUser = "Usuario registrado";
    }

    public enum RoleType
    {
        [Description("Administrador")]
        Administrator,
        [Description("Usuario registrado")]
        RegisteredUser
    }
}