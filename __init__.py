from binaryninja import *

def do_nothing(bv):
	show_message_box("Do Nothing", "Congratulations! You have successfully done nothing.\n\n" +
					 "Pat yourself on the back.", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

PluginCommand.register("Useless Plugin", "Basically does nothing", do_nothing)
