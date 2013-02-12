using LoadOpenSslKeys.Model;
using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Input;

namespace LoadOpenSslKeys.ViewModel
{
    public class MainViewModel : DependencyObject, INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        // Using a DependencyProperty as the backing store for RSAData.  This enables animation, styling, binding, etc...
        public static readonly DependencyProperty RSADataProperty = DependencyProperty.Register("RSAData", 
                                                                                                typeof(RSACryptoServiceProvider), 
                                                                                                typeof(MainViewModel), 
                                                                                                new FrameworkPropertyMetadata(null));

        private ICommand commandBrowse = null;
        private ICommand commandExit = null;
        private ICommand commandLoadKeys = null;

        public string KeysDescription
        {
            get
            {
                return "Select file with key\n" +
                    "Acceptable formats: OpenSSL Public/Private key, PKCS #8 Private key and PKCS #8 (Encrypted) Private key.\n";
            }
        }

        /// <summary>
        /// Gets or sets the name of the file.
        /// </summary>
        /// <value>
        /// The name of the file.
        /// </value>
        public string FileName
        {
            get;
            set;
        }

        public RSACryptoServiceProvider RSAData
        {
            get { return (RSACryptoServiceProvider)GetValue(RSADataProperty); }
            set { SetValue(RSADataProperty, value); }
        }


        #region Command Browse
        public ICommand CommandBrowse
        {
            get
            {
                if (commandBrowse == null)
                    commandBrowse = new CommandBrowse(this);

                return commandBrowse;
            }
        }

        internal bool CanExecuteBrowseCommand(object parameter)
        {
            return true;
        }

        internal void ExecuteBrowseCommand(object parameter)
        {
            OpenFileDialog dlg = new OpenFileDialog()
            {
                CheckFileExists = true,
                CheckPathExists = true,
                DefaultExt = ".pem",
                Filter = "PEM files|*.pem|All files|*.*",
                InitialDirectory = Environment.CurrentDirectory,
                Multiselect = false,
                RestoreDirectory = true,
                ShowReadOnly = true,
                Title = "Select PEM file with keys"
            };

            bool? result = dlg.ShowDialog();
            if ((result.HasValue == false) || (result.Value == false))
                return;

            this.FileName = dlg.FileName;
        }
        #endregion

        #region Command Exit
        public ICommand CommandExit
        {
            get
            {
                if (commandExit == null)
                    commandExit = new CommandExit(this);

                return commandExit;
            }
        }

        internal bool CanExecuteExitCommand(object parameter)
        {
            return true;
        }

        internal void ExecuteExitCommand(object parameter)
        {
            Application.Current.Shutdown();
        }
        #endregion

        #region Command LoadKeys
        public ICommand CommandLoadKeys
        {
            get
            {
                if (commandLoadKeys == null)
                    commandLoadKeys = new CommandLoadKeys(this);

                return commandLoadKeys;
            }
        }

        internal bool CanExecuteCommandLoadKeys(object parameter)
        {
            if (string.IsNullOrEmpty(this.FileName))
                return false;

            return true;
        }

        internal void ExecuteCommandLoadKeys(object parameter)
        {
            MainModel model = new MainModel();
            this.RSAData = model.LoadKeysFile(this.FileName);

            if (PropertyChanged != null)
                PropertyChanged(this, new PropertyChangedEventArgs("RSAData"));
        }
        #endregion
    }
}
