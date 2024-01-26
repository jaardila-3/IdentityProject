using IdentityProject.DataAccess.Interfaces.Repositories;
using IdentityProject.DataAccess.Persistence;

namespace IdentityProject.DataAccess.Repositories.Identity;
public class UnitOfWorkIdentity(ApplicationDbContext context) : IUnitOfWork
{
    private Dictionary<string, object>? _repositories;
    private readonly ApplicationDbContext _context = context;
    private IRolesRepository? _rolesRepository;
    public IRolesRepository RolesRepository => _rolesRepository ??= new RolesRepository(_context);

    public IRepositoryReadWrite<T>? Repository<T>() where T : class
    {
        _repositories ??= [];

        var type = typeof(T).Name;

        if (!_repositories.ContainsKey(type))
        {
            var repositoryType = typeof(RepositoryIdentity<>);
            var repositoryInstance = Activator.CreateInstance(repositoryType.MakeGenericType(typeof(T)), _context)
                ?? throw new InvalidOperationException("Error al crear la instancia del repositorio");

            _repositories.Add(type, repositoryInstance);
        }

        return (IRepositoryReadWrite<T>?)_repositories[type];
    }

    public async Task<int> SaveChangesAsync() => await _context.SaveChangesAsync();

    private bool disposed = false;
    protected virtual void Dispose(bool disposing)
    {
        if (!disposed)
        {
            if (disposing) _context.Dispose();
        }
        disposed = true;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}