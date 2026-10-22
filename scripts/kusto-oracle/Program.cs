// Prints one JSON object per input file: whether Kusto.Language's parser
// accepts it, and the syntax diagnostics it reports when it does not.
using System.Text.Json;
using Kusto.Language;

var options = new JsonSerializerOptions { WriteIndented = false };
foreach (var path in args)
{
    var code = KustoCode.Parse(File.ReadAllText(path));
    var diagnostics = code.GetSyntaxDiagnostics()
        .Where(d => d.Severity == DiagnosticSeverity.Error)
        .Select(d => new { code = d.Code, message = d.Message, start = d.Start, length = d.Length })
        .ToList();
    Console.WriteLine(JsonSerializer.Serialize(
        new { path, kind = code.Kind, accepted = diagnostics.Count == 0, diagnostics },
        options));
}
