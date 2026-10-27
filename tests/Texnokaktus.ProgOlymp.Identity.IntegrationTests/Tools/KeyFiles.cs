namespace Texnokaktus.ProgOlymp.Identity.IntegrationTests.Tools;

public sealed class KeyFiles : IDisposable
{
    public string DirectoryPath { get; } = Path.Combine(AppContext.BaseDirectory, $"jwt-tests-{Guid.NewGuid():N}");
    private readonly List<string> files = [];
    private readonly List<string> directories = [];

    public KeyFiles()
    {
        Directory.CreateDirectory(DirectoryPath);
        directories.Add(DirectoryPath);
    }

    public string WriteKey(string name, string pem)
    {
        var path = Path.Combine(DirectoryPath, name);
        files.Add(path);
        File.WriteAllText(path, pem);
        return path;
    }

    public void WriteDefaultKey(string pem)
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "keys");
        if (!Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
            directories.Add(directory);
        }

        var path = Path.Combine(directory, "jwt-public.pem");
        // Do not overwrite or later delete a key that this test did not create.
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write);
        files.Add(path);
        using var writer = new StreamWriter(file);
        writer.Write(pem);
    }

    public void Dispose()
    {
        foreach (var file in files)
            File.Delete(file);
        files.Clear();

        foreach (var directory in directories.AsEnumerable().Reverse())
            Directory.Delete(directory);
        directories.Clear();
    }
}
