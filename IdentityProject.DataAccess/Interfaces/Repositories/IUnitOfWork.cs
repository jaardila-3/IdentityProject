namespace IdentityProject.DataAccess.Interfaces.Repositories;
public interface IUnitOfWork : IDisposable
{
    IRolesRepository RolesRepository { get; }
    IRepositoryReadWrite<T>? Repository<T>() where T : class;
    Task<int> SaveChangesAsync();
}
