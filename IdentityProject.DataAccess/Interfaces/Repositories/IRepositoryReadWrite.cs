namespace IdentityProject.DataAccess.Interfaces.Repositories;
public interface IRepositoryReadWrite<T> : IRepositoryReadQueries<T>, IRepositoryWriteCommands<T> where T : class
{

}