using MyPC.LanPrintDoctor.Abstractions.Validation;

namespace MyPC.LanPrintDoctor.UnitTests;

public class InputValidatorTests
{
    [Theory]
    [InlineData("192.168.1.10", true)]
    [InlineData("server01", true)]
    [InlineData("server_01", false)]
    [InlineData("192.168.1.10; calc.exe", false)]
    [InlineData("", false)]
    [InlineData("$(whoami)", false)]
    public void TryParseHost_RejectsInjection(string input, bool expected)
    {
        var ok = InputValidator.TryParseHost(input, out _);
        Assert.Equal(expected, ok);
    }
}
