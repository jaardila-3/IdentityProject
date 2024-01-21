namespace IdentityProject.DataAccess.Interfaces.Repositories;
public interface IRepositoryWriteCommands<T> where T : class
{
    void InsertEntity(T entity);

    void UpdateEntity(T entity);

    void DeleteEntity(T entity);
}