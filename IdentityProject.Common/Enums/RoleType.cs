using System.ComponentModel;

namespace IdentityProject.Common.Enums
{
    public enum RoleType
    {
        [Description("Administrador")]
        Admin,
        [Description("Usuario registrado")]
        Usuario_Registrado
    }

    public static class RoleTypeString
    {
        public static readonly string Admin = "Administrador";
        public static readonly string Usuario_Registrado = "Usuario registrado";
    }
}