using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace LoadOpenSslKeys.ViewModel
{
    public class CommandLoadKeys : ICommand
    {
        private MainViewModel viewModel;

        public CommandLoadKeys(MainViewModel viewModel)
        {
            this.viewModel = viewModel;
        }

        public bool CanExecute(object parameter)
        {
            return viewModel.CanExecuteCommandLoadKeys(parameter);
        }

        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }

        public void Execute(object parameter)
        {
            viewModel.ExecuteCommandLoadKeys(parameter);
        }
    }
}
