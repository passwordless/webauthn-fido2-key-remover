using CliWrap;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace webauthn_fido2_key_remover
{
    class Program
    {

        private static Dictionary<string, string> WELL_KNOWN = new Dictionary<string, string>() {
            {"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763","localhost" },
            {"f1ad9ac3edf2aa5a40daf387493fd145a8a77646aa580136153d1164c7fd84ea", "passwordless.dev" }
        };

        static async Task Main(string[] args)
        {
            AnsiConsole.Render(
                new FigletText("Passwordless.dev")
                .LeftAligned()
                .Color(Color.Yellow));

            AnsiConsole.MarkupLine("A small tool built by Anders at Passwordless.dev to remove Windows 10 WebAuthn Keys");
            AnsiConsole.MarkupLine("[bold]Note:[/] To delete keys, you need to run this tool as administrator. If you do not want to do that, you can run `certutil -csp NGC -delkey <name>` manually.");

            //certutil -csp NGC -key

            string keyString = "";
            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Arc)
                .StartAsync("Loading fido2 keys", async ctx =>
                {
                    string error = "";

                    (keyString, error) = await CertUtil("-csp NGC -key");
                });

            // Parse cert util response
            var keys = new List<FidoObject>();
            using (StringReader reader = new StringReader(keyString))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.Contains("FIDO"))
                    {
                        var details = line.Split("FIDO_AUTHENTICATOR//")[1];
                        var result = details.Split("_");
                        var f = new FidoObject() { Name = line, RpIdHash = result[0], UsernameHEX = result[1], Id = keys.Count + 1 };
                        keys.Add(f);
                    }
                }
            }

            AnsiConsole.MarkupLine("[bold]Found " + keys.Count + " keys.[/]");


            var keysToBeDeleted = AnsiConsole.Prompt(
    new MultiSelectionPrompt<string>()
        .Title("Select keys to [red]delete[/]:")
        .NotRequired() // Not required to have a favorite fruit
        .PageSize(8)
        .HighlightStyle(new Style(Color.Red, null, Decoration.Underline))
        .MoreChoicesText("[grey](Move up and down to reveal more keys)[/]")
        .InstructionsText(
            "[grey](Press [red]<space>[/] to toggle a key, " +
            "[green]<enter>[/] to procceed with removal)[/]")
        .AddChoices(keys.Select(x =>
            (x.Id + ". " + Markup.Escape(x.Username)).PadRight(20) + " - ".PadRight(5) + RPName(x.RpIdHash)))
        );


            if (keysToBeDeleted.Count > 0)
            {

                AnsiConsole.MarkupLine("Selected keys: ");
                foreach (var k in keysToBeDeleted)
                {
                    AnsiConsole.MarkupLine(k);
                }

                if (!AnsiConsole.Confirm("Delete " + keysToBeDeleted.Count + " keys?"))
                {
                    return;
                }

                foreach (var key in keysToBeDeleted)
                {
                    var rule = new Rule("[red]Deleting... [/]" + key);
                    rule.Alignment = Justify.Left;
                    AnsiConsole.Render(rule);

                    var id = Convert.ToInt32(key.Split(".")[0]);
                    var name = keys.Single(x => x.Id == id).Name;
                    AnsiConsole.MarkupLine("[grey]certutil -csp NGC -delkey" + name + "[/]");
                    var (res, error) = await CertUtil("-csp NGC -delkey " + name);

                    AnsiConsole.MarkupLine("[grey]{0}[/]", Markup.Escape(res));
                }
            }


            Console.WriteLine("Program done... press anything to exit.");
            Console.ReadLine();
        }

        static private string RPName(string hash)
        {
            if (WELL_KNOWN.ContainsKey(hash))
            {
                return $"({WELL_KNOWN[hash]}) {hash}";
            }

            return hash;
        }

        /// <summary>
        /// Runs a PowerShell script with parameters and prints the resulting pipeline objects to the console output. 
        /// </summary>
        /// <param name="scriptContents">The script file contents.</param>
        /// <param name="scriptParameters">A dictionary of parameter names and parameter values.</param>
        static public async Task<(string result, string error)> CertUtil(string command)
        {
            var stdOutBuffer = new StringBuilder();
            var stdErrBuffer = new StringBuilder();
            var result = await Cli.Wrap("certutil")
                .WithArguments(command)
                .WithStandardOutputPipe(PipeTarget.ToStringBuilder(stdOutBuffer))
                    .WithStandardErrorPipe(PipeTarget.ToStringBuilder(stdErrBuffer))
                    .WithValidation(CommandResultValidation.None)
                .ExecuteAsync();

            return (stdOutBuffer.ToString(), stdErrBuffer.ToString());
        }




        public class FidoObject
        {

            private static System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();
            public string Name { get; set; }
            public string UsernameHEX { get; set; }
            public string Username
            {
                get
                {
                    return encoding.GetString(StringToByteArray(UsernameHEX));
                }
            }
            public string RpIdHash { get; set; }
            public int Id { get; internal set; }
        }

        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
