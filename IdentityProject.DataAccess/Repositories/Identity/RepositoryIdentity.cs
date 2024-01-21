using System.Linq.Expressions;
using IdentityProject.DataAccess.Interfaces.Repositories;
using IdentityProject.DataAccess.Persistence;
using Microsoft.EntityFrameworkCore;

namespace IdentityProject.DataAccess.Repositories.Identity
{
    public class RepositoryIdentity<T>(ApplicationDbContext context) : IRepositoryReadWrite<T> where T : class
    {
        protected readonly ApplicationDbContext _context = context;

        public async Task<IReadOnlyList<T>> GetListAsync(Expression<Func<T, bool>>? predicate = null,
                                     Func<IQueryable<T>, IOrderedQueryable<T>>? orderBy = null,
                                     List<Expression<Func<T, object>>>? includes = null,
                                     bool disableTracking = true)
        {

            IQueryable<T> query = _context.Set<T>();
            if (disableTracking)
                query = query.AsNoTracking();

            if (includes is not null)
                query = includes.Aggregate(query, (current, include) => current.Include(include));

            if (predicate is not null)
                query = query.Where(predicate);

            if (orderBy is not null)
                return await orderBy(query).ToListAsync();

            return await query.ToListAsync();
        }

        public virtual async Task<T?> GetByIdAsync(string id) => await _context.Set<T>().FindAsync(id);

        public void InsertEntity(T entity) => _context.Set<T>().Add(entity);

        public void UpdateEntity(T entity)
        {
            _context.Set<T>().Attach(entity);
            _context.Entry(entity).State = EntityState.Modified;
        }

        public void DeleteEntity(T entity) => _context.Set<T>().Remove(entity);
    }
}