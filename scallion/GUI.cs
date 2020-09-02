using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Threading;

namespace scallion
{
    public partial class GUI : Form
    {
        private bool isGenerating = false;

        public GUI()
        {
            InitializeComponent();

            this.KeyDown += _KeyDown;
        }

        public void PushResult(string str)
        {
            this.Results.Items.Add(str);
        }

        public void SetStatus(string str)
        {
            this.StatusText.Text = str;
        }

        private void beginShitting()
        {
            ProgramParameters parms = ProgramParameters.Instance;

            // If no Work Group Size provided, then query the selected device for preferred, if not found set to 32.
            if (parms.WorkGroupSize == 0)
            {
                ulong preferredWorkGroupSize = 32;
                uint deviceId = 0;
                foreach (CLDeviceInfo device in CLRuntime.GetDevices())
                {
                    if (!device.CompilerAvailable) continue;
                    if (deviceId == parms.DeviceId)
                    {
                        preferredWorkGroupSize = Program.getPreferredWorkGroupSize(device.DeviceId);
                        break;
                    }
                    deviceId++;
                }

                parms.WorkGroupSize = (uint)preferredWorkGroupSize;
            }

            try
            {
                Console.CancelKeyPress += new ConsoleCancelEventHandler(Program.Console_CancelKeyPress);
                Program._runtime.Run(ProgramParameters.Instance);
            }
            catch (ApplicationException e)
            {
                // these are handled and printed out
                Console.Error.WriteLine(e.Message);
                Environment.Exit(1);
            }
            finally
            {
                Program.Shutdown();
            }

            this.isGenerating = false;
        }

        private void StartBtn_Click(object sender, EventArgs e)
        {
            if (!isGenerating)
            {
                if (SearchTerm.Text.Length == 0) return;
                if (OutputLoc.Text.Length == 0) return;

                Program._runtime.Abort = false;

                ProgramParameters parms = ProgramParameters.Instance;
                parms.ProgramMode = Mode.Normal;
                parms.Regex = SearchTerm.Text;
                parms.KeyOutputPath = OutputLoc.Text;
                parms.TextMode = NoNumbers.Checked;
                parms.ContinueGeneration = InfiniteMode.Checked;

                Thread t = new Thread(new ThreadStart(beginShitting));
                t.SetApartmentState(ApartmentState.STA);
                t.Start();

                this.StatusText.Text = "Started!";

                this.StartBtn.ForeColor = Color.Red;
                this.StartBtn.Text = "Stop";

                this.isGenerating = true;
            } else
            {
                StatusText.Text = "Shut down.";
                Console.Write("User requested shutdown.");
                Program._runtime.Abort = true;
                Program.Shutdown();

                this.StartBtn.ForeColor = Color.Green;
                this.StartBtn.Text = "Start";
                
                this.isGenerating = false;
            }
        }

        private void _KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.C && e.Modifiers == Keys.Control)
            {
                Clipboard.SetText(Results.SelectedItem.ToString().Split(' ')[0]);
                StatusText.Text = "Copied to clipboard.";
            }
        }

        private void Results_SelectedIndexChanged(object sender, EventArgs e)
        {

        }
    }
}
