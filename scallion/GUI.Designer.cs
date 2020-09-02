namespace scallion
{
    partial class GUI
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(GUI));
            this.Results = new System.Windows.Forms.ListBox();
            this.SearchTerm = new System.Windows.Forms.TextBox();
            this.OutputLoc = new System.Windows.Forms.TextBox();
            this.StartBtn = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.InfiniteMode = new System.Windows.Forms.CheckBox();
            this.NoNumbers = new System.Windows.Forms.CheckBox();
            this.StatusText = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // Results
            // 
            this.Results.Font = new System.Drawing.Font("Courier New", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Results.FormattingEnabled = true;
            this.Results.ItemHeight = 15;
            this.Results.Location = new System.Drawing.Point(12, 12);
            this.Results.Name = "Results";
            this.Results.Size = new System.Drawing.Size(299, 169);
            this.Results.TabIndex = 0;
            this.Results.SelectedIndexChanged += new System.EventHandler(this.Results_SelectedIndexChanged);
            // 
            // SearchTerm
            // 
            this.SearchTerm.Location = new System.Drawing.Point(101, 191);
            this.SearchTerm.Name = "SearchTerm";
            this.SearchTerm.Size = new System.Drawing.Size(210, 20);
            this.SearchTerm.TabIndex = 1;
            // 
            // OutputLoc
            // 
            this.OutputLoc.Location = new System.Drawing.Point(101, 217);
            this.OutputLoc.Name = "OutputLoc";
            this.OutputLoc.Size = new System.Drawing.Size(210, 20);
            this.OutputLoc.TabIndex = 2;
            // 
            // StartBtn
            // 
            this.StartBtn.Font = new System.Drawing.Font("Reem Kufi", 12F);
            this.StartBtn.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(192)))), ((int)(((byte)(0)))));
            this.StartBtn.Location = new System.Drawing.Point(317, 191);
            this.StartBtn.Name = "StartBtn";
            this.StartBtn.Size = new System.Drawing.Size(85, 46);
            this.StartBtn.TabIndex = 3;
            this.StartBtn.Text = "Start";
            this.StartBtn.UseVisualStyleBackColor = true;
            this.StartBtn.Click += new System.EventHandler(this.StartBtn_Click);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(12, 194);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(68, 13);
            this.label1.TabIndex = 4;
            this.label1.Text = "Search Term";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(12, 220);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(83, 13);
            this.label2.TabIndex = 5;
            this.label2.Text = "Output Location";
            // 
            // InfiniteMode
            // 
            this.InfiniteMode.AutoSize = true;
            this.InfiniteMode.Location = new System.Drawing.Point(317, 12);
            this.InfiniteMode.Name = "InfiniteMode";
            this.InfiniteMode.Size = new System.Drawing.Size(57, 17);
            this.InfiniteMode.TabIndex = 6;
            this.InfiniteMode.Text = "Infinite";
            this.InfiniteMode.UseVisualStyleBackColor = true;
            // 
            // NoNumbers
            // 
            this.NoNumbers.AutoSize = true;
            this.NoNumbers.Location = new System.Drawing.Point(317, 36);
            this.NoNumbers.Name = "NoNumbers";
            this.NoNumbers.Size = new System.Drawing.Size(85, 17);
            this.NoNumbers.TabIndex = 7;
            this.NoNumbers.Text = "No Numbers";
            this.NoNumbers.UseVisualStyleBackColor = true;
            // 
            // StatusText
            // 
            this.StatusText.AutoSize = true;
            this.StatusText.Font = new System.Drawing.Font("Microsoft Sans Serif", 6.75F, System.Drawing.FontStyle.Italic, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.StatusText.Location = new System.Drawing.Point(318, 172);
            this.StatusText.Name = "StatusText";
            this.StatusText.Size = new System.Drawing.Size(35, 12);
            this.StatusText.TabIndex = 8;
            this.StatusText.Text = "Ready!";
            // 
            // GUI
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(412, 247);
            this.Controls.Add(this.StatusText);
            this.Controls.Add(this.NoNumbers);
            this.Controls.Add(this.InfiniteMode);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.StartBtn);
            this.Controls.Add(this.OutputLoc);
            this.Controls.Add(this.SearchTerm);
            this.Controls.Add(this.Results);
            this.Cursor = System.Windows.Forms.Cursors.Default;
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.Name = "GUI";
            this.Text = "Tor Address Generator";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ListBox Results;
        private System.Windows.Forms.TextBox SearchTerm;
        private System.Windows.Forms.TextBox OutputLoc;
        private System.Windows.Forms.Button StartBtn;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.CheckBox InfiniteMode;
        private System.Windows.Forms.CheckBox NoNumbers;
        private System.Windows.Forms.Label StatusText;
    }
}