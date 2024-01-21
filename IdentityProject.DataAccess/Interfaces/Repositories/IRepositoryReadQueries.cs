using System.Linq.Expressions;

namespace IdentityProject.DataAccess.Interfaces.Repositories;
public interface IRepositoryReadQueries<T> where T : class
{
    Task<T?> GetByIdAsync(string id);

    Task<IReadOnlyList<T>> GetListAsync(Expression<Func<T, bool>>? predicate = null,
                                 Func<IQueryable<T>, IOrderedQueryable<T>>? orderBy = null,
                                 List<Expression<Func<T, object>>>? includes = null,
                                 bool disableTracking = true);

}