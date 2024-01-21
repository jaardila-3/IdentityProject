namespace IdentityProject.DataAccess.Interfaces.Repositories;
public interface IUnitOfWork : IDisposable
{
    IRepositoryReadWrite<T>? Repository<T>() where T : class;
    Task<int> SaveChangesAsync();
}
