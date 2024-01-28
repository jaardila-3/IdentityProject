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
}