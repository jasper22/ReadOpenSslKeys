using System;
using System.Windows.Input;

namespace LoadOpenSslKeys.ViewModel
{
    public class CommandBrowse : ICommand
    {
        private MainViewModel viewModel;

        public CommandBrowse(MainViewModel viewModel)
        {
            this.viewModel = viewModel;
        }

        public bool CanExecute(object parameter)
        {
            return viewModel.CanExecuteBrowseCommand(parameter);
        }

        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }

        public void Execute(object parameter)
        {
            viewModel.ExecuteBrowseCommand(parameter);
        }
    }
}
