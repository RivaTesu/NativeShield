using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using dnlib.DotNet;

namespace NativeShield;

internal static class Program
{
    private const string PVs =
        @"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat";

    private const string PNs = @"C:\Users\danie\OneDrive\Documents\GitHub\NativeShield\NativeShield\Helpers";

    private static void Main(string[] args)
    {
        if (args.Length <= 0)
        {
            Console.WriteLine(Utils.Logger("Invalid args."));
            Console.ReadLine();
            return;
        }

        var key = ("NShield_" + Guid.NewGuid().ToString("n").Substring(0, 12)).ToCharArray();
        var kName = Utils.GenerateName();
        var kAName = Utils.GenerateName();
        var kLength = Utils.GenerateName();
        var rDName = Utils.GenerateName();
        var fNameCpp = Utils.GenerateName();

        var kRead = key.Aggregate(string.Empty, (current, keyParse) => current + "\'" + keyParse + "\', ");

        var methodName = DetectConsole(args[0])
            ? "int main()"
            : "int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)";

        CompileShield(args[0], key, kName, kAName, kLength, rDName, fNameCpp, kRead, methodName);

        Console.WriteLine(Utils.Logger("Done!"));
        Console.ReadLine();
    }

    private static bool DetectConsole(string path)
    {
        var isConsole = false;

        var moduleDefMd = ModuleDefMD.Load(path);

        switch (moduleDefMd.Kind)
        {
            case ModuleKind.Console:
                isConsole = true;
                Console.WriteLine(Utils.Logger($"Working with: {ModuleKind.Console}"));
                break;
            case ModuleKind.Windows:
                Console.WriteLine(Utils.Logger($"Working with: {ModuleKind.Windows}"));
                break;
            case ModuleKind.Dll:
                Console.WriteLine(Utils.Logger($"Native shielding does not support: {ModuleKind.Dll}"));
                break;
            case ModuleKind.NetModule:
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }

        return isConsole;
    }

    private static void CompileShield(string path, char[] key, string kName, string kAName, string kLength,
        string rDName, string fNameCpp, string kRead, string methodName)
    {
        try
        {
            Console.WriteLine(Utils.Logger("Setting up writing cpp file..."));

            var shieldCode =
                $"#include <cstdlib>\r\n#include <iostream>\r\n#include <sstream>\r\n#include \"stdafx.h\"\r\n#include <cassert>\r\n#include <fstream>\r\n#include \"rawData.h\"\r\n#include \"lazy_importer.hpp\"\r\n#pragma region Includes and Imports\r\n			#include <windows.h>\r\n			#include <metahost.h>\r\n			#pragma comment(lib, \"mscoree.lib\")\r\n			#import \"mscorlib.tlb\" raw_interfaces_only\\\r\n			high_property_prefixes(\"_get\",\"_put\",\"_putref\")\\\r\n			rename(\"ReportEvent\", \"InteropServices_ReportEvent\")\r\n			using namespace mscorlib;\r\n			using namespace std;\r\n	#pragma endregion\r\n{methodName}\r\n{{\r\nBOOL isDebuggerPresent = FALSE;\r\nif (IsDebuggerPresent())\r\n	exit(0);\r\nif (LI_FN(CheckRemoteDebuggerPresent)(GetCurrentProcess(), &isDebuggerPresent))\r\n	if (isDebuggerPresent)\r\n		exit(0);\r\nLI_FN(CoInitializeEx);\r\nstring {kAName} = \"{kLength}\";\r\nchar {kName}[{key.Length}] = {{ {kRead} }};\r\nfor (int i = 0; i < sizeof({rDName}); i++)\r\n    {rDName}[i] = {rDName}[i] ^ {kName}[i % sizeof({kName})] + {kAName}.length();\r\nICLRMetaHost* pMetaHost = NULL;\r\nICLRMetaHostPolicy* pMetaHostPolicy = NULL;\r\nICLRDebugging* pCLRDebugging = NULL;\r\nHRESULT hr;\r\nhr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost,\r\n(LPVOID*)& pMetaHost);\r\nhr = CLRCreateInstance(CLSID_CLRMetaHostPolicy, IID_ICLRMetaHostPolicy,\r\n(LPVOID*)& pMetaHostPolicy);\r\nhr = CLRCreateInstance(CLSID_CLRDebugging, IID_ICLRDebugging,\r\n(LPVOID*)& pCLRDebugging);\r\nICLRRuntimeInfo* pRuntimeInfo = NULL;\r\nhr = pMetaHost->GetRuntime(L\"v4.0.30319\", IID_ICLRRuntimeInfo, (VOID **)& pRuntimeInfo);\r\nBOOL bLoadable;\r\nhr = pRuntimeInfo->IsLoadable(&bLoadable);\r\nICorRuntimeHost* pRuntimeHost = NULL;\r\nhr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&pRuntimeHost);\r\nhr = pRuntimeHost->Start();\r\nIUnknownPtr pAppDomainThunk = NULL;\r\nhr = pRuntimeHost->GetDefaultDomain(&pAppDomainThunk);\r\n_AppDomainPtr pDefaultAppDomain = NULL;\r\nhr = pAppDomainThunk->QueryInterface(__uuidof(_AppDomain), (VOID * *)& pDefaultAppDomain);\r\n_AssemblyPtr pAssembly = NULL;\r\nSAFEARRAYBOUND rgsabound[1];\r\nrgsabound[0].cElements = sizeof({rDName});\r\nrgsabound[0].lLbound = 0;\r\nSAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);\r\nvoid* pvData = NULL;\r\nhr = SafeArrayAccessData(pSafeArray, &pvData);\r\nOutputDebugString(TEXT(\"%s%s%s%s%s%s%s%s%s%s%s\"));\r\nLI_FN(memcpy)(pvData, {rDName}, sizeof({rDName}));\r\nhr = SafeArrayUnaccessData(pSafeArray);\r\nhr = pDefaultAppDomain->Load_3(pSafeArray, &pAssembly);\r\n_MethodInfoPtr pMethodInfo = NULL;\r\nhr = pAssembly->get_EntryPoint(&pMethodInfo);\r\nVARIANT retVal;\r\nZeroMemory(&retVal, sizeof(VARIANT));\r\nVARIANT obj;\r\nZeroMemory(&obj, sizeof(VARIANT));\r\nobj.vt = VT_NULL;\r\nSAFEARRAY* psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 0);\r\nhr = pMethodInfo->Invoke_3(obj, psaStaticMethodArgs, &retVal);\r\nif (FAILED(hr)) {{\r\n	hr = pMethodInfo->Invoke_3(obj, SafeArrayCreateVector(VT_VARIANT, 0, 1), &retVal);\r\n}}\r\nif (pRuntimeHost) {{ pRuntimeHost->Release(); pRuntimeHost = nullptr; }}\r\nif (pRuntimeInfo) {{ pRuntimeInfo->Release(); pRuntimeInfo = nullptr; }}\r\nif (pMetaHost) {{ pMetaHost->Release(); pMetaHost = nullptr; }}\r\nreturn 0;\r\n}}\r\n";

            File.WriteAllText($"{PNs}\\{fNameCpp}.cpp", shieldCode);

            Console.WriteLine(Utils.Logger($"File: {fNameCpp}.cpp written."));
            Console.WriteLine(Utils.Logger("Setting up raw data parse.."));

            var stringBuilder = new StringBuilder();

            var byteKey = Encoding.ASCII.GetBytes(key);
            var bytes = EncryptDecrypt(File.ReadAllBytes(path), byteKey, kLength.Length);

            stringBuilder.Append($"unsigned char {rDName}[{bytes.Length}] = {{");

            foreach (var hex in bytes)
                stringBuilder.Append($"0x{hex:X2},");

            stringBuilder.Append("};");

            Console.WriteLine(Utils.Logger(
                $"Raw data parsed from file: {Path.GetFileNameWithoutExtension(path) + Path.GetExtension(path)}"));

            File.WriteAllText($"{PNs}\\rawData.h", stringBuilder.ToString());

            Console.WriteLine(Utils.Logger("Raw data saved!"));
            Console.WriteLine(Utils.Logger("Setting up compiler cl.."));

            #region Compiler

            var compiler = new Process();
            compiler.StartInfo.FileName = "cmd.exe";
            compiler.StartInfo.WorkingDirectory = Path.GetTempPath();
            compiler.StartInfo.RedirectStandardInput = true;
            compiler.StartInfo.RedirectStandardOutput = true;
            compiler.StartInfo.UseShellExecute = false;
            compiler.StartInfo.WindowStyle = ProcessWindowStyle.Normal;
            compiler.Start();
            compiler.StandardInput.WriteLine($"\"{PVs}\"");
            compiler.StandardInput.WriteLine($@"cl.exe /MT /nologo /EHsc {PNs}\{fNameCpp}.cpp");
            compiler.StandardInput.WriteLine(@"exit");
            compiler.WaitForExit();

            File.Copy($"{Path.GetTempPath()}\\{fNameCpp}.exe",
                $"{Environment.CurrentDirectory}\\{Path.GetFileNameWithoutExtension(path)}_Shielded{Path.GetExtension(path)}",
                true);

            #endregion
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
        finally
        {
            File.Delete($"{Path.GetTempPath()}\\{fNameCpp}.obj");
            File.Delete($"{Path.GetTempPath()}\\mscorlib.tlh");
            File.Delete($"{Path.GetTempPath()}\\{fNameCpp}.exe");
            File.Delete($"{PNs}\\{fNameCpp}.cpp");
            File.Delete($"{PNs}\\rawData.h");
        }
    }

    private static byte[] EncryptDecrypt(byte[] data, IReadOnlyList<byte> key, int kLength)
    {
        for (var i = 0; i < data.Length; ++i)
            data[i] = (byte)(data[i] ^ (key[i % key.Count] + kLength));

        return data;
    }
}