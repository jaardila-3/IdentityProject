using System.ComponentModel;

namespace IdentityProject.Web.Models.Enum
{
    public enum RoleType
    {
        [Description("Administrador")]
        Admin,
        [Description("Usuario registrado")]
        RegisteredUser
    }
}