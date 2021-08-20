using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using dnlib.DotNet;

namespace NativeShield
{
    class Program
    {
        private const string pVS = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat";
        private const string pNS = "C:\\Users\\RivaTesu\\Desktop\\Coisas\\Projetos\\Obfuscator\\NativeShield\\Helpers";

        static void Main(string[] args)
        {
            if(args.Length <= 0)
            {
                Console.WriteLine(Utils.Log("Error args."));
                Console.ReadLine();
                return;
            }

            var key = ("NShield_" + Guid.NewGuid().ToString("n").Substring(0, 12)).ToCharArray();
            var kName = Utils.GenerateName();
            var kAName = Utils.GenerateName();
            var kLength = Utils.GenerateName();
            var rDName = Utils.GenerateName();
            var fNameCPP = Utils.GenerateName();

            string kRead = string.Empty;

            foreach (var keyParse in key)
                kRead += "\'" + keyParse + "\', ";

            string methodName = detectConsole(args[0]) ? "int main()" : "int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)";
          
            compileShield(args[0], key, kName, kAName, kLength, rDName, fNameCPP, kRead, methodName);
            
            Console.WriteLine(Utils.Log("Done!"));
            Console.ReadLine();
        }

        static bool detectConsole(string path)
        {
            bool isConsole = false;

            ModuleDefMD moduleDefMD = ModuleDefMD.Load(path);

            if (moduleDefMD.Kind == ModuleKind.Console)
            {
                isConsole = true;
                Console.WriteLine(Utils.Log($"Work with: {ModuleKind.Console}"));
            }
            else if(moduleDefMD.Kind == ModuleKind.Windows)
                Console.WriteLine(Utils.Log($"Work with: {ModuleKind.Windows}"));
            else if(moduleDefMD.Kind == ModuleKind.Dll)
                Console.WriteLine(Utils.Log($"Native shield not support: {ModuleKind.Dll}"));
            return isConsole;
        }

        static void compileShield(string path, char[] key, string kName, string kAName, string kLength, string rDName, string fNameCPP, string kRead, string methodName)
        {
            try
            {
                Console.WriteLine(Utils.Log("Setting up writting cpp file..."));

                #region ShieldCode
                string content =
                    $"#include <cstdlib>\r\n" +
                    $"#include <iostream>\r\n" +
                    $"#include <sstream>\r\n" +
                    $"#include \"stdafx.h\"\r\n" +
                    $"#include <cassert>\r\n" +
                    $"#include <fstream>\r\n" +
                    $"#include \"rawData.h\"\r\n" +
                    $"#include \"lazy_importer.hpp\"\r\n" +
                    $"#pragma region Includes and Imports\r\n" +
                    $"			#include <windows.h>\r\n" +
                    $"			#include <metahost.h>\r\n" +
                    $"			#pragma comment(lib, \"mscoree.lib\")\r\n" +
                    $"			#import \"mscorlib.tlb\" raw_interfaces_only\\\r\n" +
                    $"			high_property_prefixes(\"_get\",\"_put\",\"_putref\")\\\r\n" +
                    $"			rename(\"ReportEvent\", \"InteropServices_ReportEvent\")\r\n" +
                    $"			using namespace mscorlib;\r\n" +
                    $"			using namespace std;\r\n" +
                    $"	#pragma endregion\r\n" +
                    $"{methodName}\r\n" +
                    $"{{\r\n" +
                    $"BOOL isDebuggerPresent = FALSE;\r\n" +
                    $"if (IsDebuggerPresent())\r\n" +
                    $"	exit(0);\r\n" +
                    $"if (LI_FN(CheckRemoteDebuggerPresent)(GetCurrentProcess(), &isDebuggerPresent))\r\n" +
                    $"	if (isDebuggerPresent)\r\n" +
                    $"		exit(0);\r\n" +
                    $"LI_FN(CoInitializeEx);\r\n" +
                    $"string {kAName} = \"{kLength}\";\r\n" +
                    $"char {kName}[{key.Length}] = {{ {kRead} }};\r\n" +
                    $"for (int i = 0; i < sizeof({rDName}); i++)\r\n" +
                    $"    {rDName}[i] = {rDName}[i] ^ {kName}[i % sizeof({kName})] + {kAName}.length();\r\n" +
                    $"ICLRMetaHost* pMetaHost = NULL;\r\n" +
                    $"ICLRMetaHostPolicy* pMetaHostPolicy = NULL;\r\n" +
                    $"ICLRDebugging* pCLRDebugging = NULL;\r\n" +
                    $"HRESULT hr;\r\n" +
                    $"hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost,\r\n" +
                    $"(LPVOID*)& pMetaHost);\r\n" +
                    $"hr = CLRCreateInstance(CLSID_CLRMetaHostPolicy, IID_ICLRMetaHostPolicy,\r\n" +
                    $"(LPVOID*)& pMetaHostPolicy);\r\n" +
                    $"hr = CLRCreateInstance(CLSID_CLRDebugging, IID_ICLRDebugging,\r\n" +
                    $"(LPVOID*)& pCLRDebugging);\r\n" +
                    $"ICLRRuntimeInfo* pRuntimeInfo = NULL;\r\n" +
                    $"hr = pMetaHost->GetRuntime(L\"v4.0.30319\", IID_ICLRRuntimeInfo, (VOID **)& pRuntimeInfo);\r\n" +
                    $"BOOL bLoadable;\r\n" +
                    $"hr = pRuntimeInfo->IsLoadable(&bLoadable);\r\n" +
                    $"ICorRuntimeHost* pRuntimeHost = NULL;\r\n" +
                    $"hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&pRuntimeHost);\r\n" +
                    $"hr = pRuntimeHost->Start();\r\n" +
                    $"IUnknownPtr pAppDomainThunk = NULL;\r\n" +
                    $"hr = pRuntimeHost->GetDefaultDomain(&pAppDomainThunk);\r\n" +
                    $"_AppDomainPtr pDefaultAppDomain = NULL;\r\n" +
                    $"hr = pAppDomainThunk->QueryInterface(__uuidof(_AppDomain), (VOID * *)& pDefaultAppDomain);\r\n" +
                    $"_AssemblyPtr pAssembly = NULL;\r\n" +
                    $"SAFEARRAYBOUND rgsabound[1];\r\n" +
                    $"rgsabound[0].cElements = sizeof({rDName});\r\n" +
                    $"rgsabound[0].lLbound = 0;\r\n" +
                    $"SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);\r\n" +
                    $"void* pvData = NULL;\r\n" +
                    $"hr = SafeArrayAccessData(pSafeArray, &pvData);\r\n" +
                    $"OutputDebugString(TEXT(\"%s%s%s%s%s%s%s%s%s%s%s\"));\r\n" +
                    $"LI_FN(memcpy)(pvData, {rDName}, sizeof({rDName}));\r\n" +
                    $"hr = SafeArrayUnaccessData(pSafeArray);\r\n" +
                    $"hr = pDefaultAppDomain->Load_3(pSafeArray, &pAssembly);\r\n" +
                    $"_MethodInfoPtr pMethodInfo = NULL;\r\n" +
                    $"hr = pAssembly->get_EntryPoint(&pMethodInfo);\r\n" +
                    $"VARIANT retVal;\r\n" +
                    $"ZeroMemory(&retVal, sizeof(VARIANT));\r\n" +
                    $"VARIANT obj;\r\n" +
                    $"ZeroMemory(&obj, sizeof(VARIANT));\r\n" +
                    $"obj.vt = VT_NULL;\r\n" +
                    $"SAFEARRAY* psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 0);\r\n" +
                    $"hr = pMethodInfo->Invoke_3(obj, psaStaticMethodArgs, &retVal);\r\n" +
                    $"if (FAILED(hr)) {{\r\n" +
                    $"	hr = pMethodInfo->Invoke_3(obj, SafeArrayCreateVector(VT_VARIANT, 0, 1), &retVal);\r\n" +
                    $"}}\r\n" +
                    $"if (pRuntimeHost) {{ pRuntimeHost->Release(); pRuntimeHost = nullptr; }}\r\n" +
                    $"if (pRuntimeInfo) {{ pRuntimeInfo->Release(); pRuntimeInfo = nullptr; }}\r\n" +
                    $"if (pMetaHost) {{ pMetaHost->Release(); pMetaHost = nullptr; }}\r\n" +
                    $"return 0;\r\n" +
                    $"}}\r\n";
                #endregion

                File.WriteAllText(pNS + $"\\{fNameCPP}.cpp", content);
                Console.WriteLine(Utils.Log($"File: {fNameCPP}.cpp writted."));
                Console.WriteLine(Utils.Log("Setting up parse Raw Data (unsigned char)..."));

                StringBuilder stringBuilder = new StringBuilder();

                string prefix = "0x";

                byte[] byteKey = Encoding.ASCII.GetBytes(key);
                byte[] bytes = EncryptDecrypt(File.ReadAllBytes(path), byteKey, kLength.Length);

                stringBuilder.Append($"unsigned char {rDName}[" + bytes.Length + "] = {");

                foreach (var hex in bytes)
                {
                    stringBuilder.Append(prefix + hex.ToString("X2") + ",");
                }

                stringBuilder.Append("};");

                Console.WriteLine(Utils.Log($"Raw Data parsed from file: {Path.GetFileNameWithoutExtension(path) + Path.GetExtension(path)}"));

                File.WriteAllText(pNS + "\\rawData.h", stringBuilder.ToString());

                Console.WriteLine(Utils.Log("Raw Data saved!"));
                Console.WriteLine(Utils.Log("Setting up compiler cl..."));

                #region Compile
                Process compiler = new Process();
                compiler.StartInfo.FileName = "cmd.exe";
                compiler.StartInfo.WorkingDirectory = Path.GetTempPath();
                compiler.StartInfo.RedirectStandardInput = true;
                compiler.StartInfo.RedirectStandardOutput = true;
                compiler.StartInfo.UseShellExecute = false;
                compiler.StartInfo.WindowStyle = ProcessWindowStyle.Normal;
                compiler.Start();
                compiler.StandardInput.WriteLine("\"" + pVS + "\"");
                compiler.StandardInput.WriteLine(@"cl.exe /MT /nologo /EHsc " + pNS + $"\\{fNameCPP}.cpp");
                compiler.StandardInput.WriteLine(@"exit");
                string output = compiler.StandardOutput.ReadToEnd();
                compiler.WaitForExit();

                Debug.Write(output);

                compiler.Close();
                File.Copy(Path.GetTempPath() + $"\\{fNameCPP}.exe", Environment.CurrentDirectory + $"\\{Path.GetFileNameWithoutExtension(path) + "_Shielded" + Path.GetExtension(path)}", true);
                #endregion
            }
            catch(Exception e)
            {
                Console.WriteLine(e);
            }
            finally
            {
                File.Delete(Path.GetTempPath() + $"\\{fNameCPP}.obj");
                File.Delete(Path.GetTempPath() + "\\mscorlib.tlh");
                File.Delete(Path.GetTempPath() + $"\\{fNameCPP}.exe");
                File.Delete(pNS + $"\\{fNameCPP}.cpp");
                File.Delete(pNS + "\\rawData.h");
            }
        }

        public static byte[] EncryptDecrypt(byte[] data, byte[] key, int kLength)
        {
            for (int i = 0; i < data.Length; i++)
                data[i] = (byte)(data[i] ^ key[i % key.Length] + kLength);
            return data;
        }
    }
}